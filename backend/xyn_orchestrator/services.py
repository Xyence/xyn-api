import hashlib
import json
import os
from typing import Any, Dict, List, Optional

from django.utils import timezone
from jsonschema import Draft202012Validator

from .models import (
    BlueprintDraftSession,
    ContextPack,
    DraftSessionVoiceNote,
    OpenAIConfig,
    Run,
    VoiceNote,
    VoiceTranscript,
)


def _contracts_root() -> str:
    return os.environ.get("XYNSEED_CONTRACTS_ROOT", "/xyn-contracts")


def _load_schema(name: str) -> Dict[str, Any]:
    path = os.path.join(_contracts_root(), "schemas", name)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _schema_for_kind(kind: str) -> str:
    mapping = {
        "solution": "SolutionBlueprintSpec.schema.json",
        "module": "ModuleSpec.schema.json",
        "bundle": "BundleSpec.schema.json",
    }
    return mapping.get(kind, "SolutionBlueprintSpec.schema.json")


def _validate_blueprint(spec: Dict[str, Any], kind: str) -> List[str]:
    schema = _load_schema(_schema_for_kind(kind))
    validator = Draft202012Validator(schema)
    errors = []
    for error in sorted(validator.iter_errors(spec), key=lambda e: e.path):
        path = ".".join(str(p) for p in error.path) if error.path else "root"
        errors.append(f"{path}: {error.message}")
    return errors


def _openai_generate_blueprint(transcript: str, kind: str, context_text: str) -> Optional[Dict[str, Any]]:
    config = OpenAIConfig.objects.first()
    if not config:
        return None
    from openai import OpenAI  # type: ignore

    client = OpenAI(api_key=config.api_key)
    if kind == "module":
        system_prompt = (
            "You are generating a ModuleSpec JSON for Xyn. "
            "Return ONLY valid JSON matching ModuleSpec schema. "
            "Use apiVersion xyn.module/v1."
        )
    elif kind == "bundle":
        system_prompt = (
            "You are generating a BundleSpec JSON for Xyn. "
            "Return ONLY valid JSON matching BundleSpec schema. "
            "Use apiVersion xyn.bundle/v1."
        )
    else:
        system_prompt = (
            "You are generating a SolutionBlueprintSpec JSON for Xyn. "
            "Return ONLY valid JSON matching SolutionBlueprintSpec schema. "
            "Use apiVersion xyn.blueprint/v1 and include releaseSpec."
        )
    if context_text:
        system_prompt = f"{context_text}\n\n{system_prompt}"
    response = client.responses.create(
        model=config.default_model,
        input=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": transcript},
        ],
    )
    try:
        return json.loads(response.output_text)
    except json.JSONDecodeError:
        return None


def get_release_target_deploy_state(release_target_id: str) -> Dict[str, Any]:
    run = (
        Run.objects.filter(
            metadata_json__release_target_id=str(release_target_id),
            metadata_json__deploy_outcome__in=["succeeded", "noop"],
        )
        .order_by("-created_at")
        .first()
    )
    if not run or not run.metadata_json:
        return {}
    meta = run.metadata_json or {}
    return {
        "run_id": str(run.id),
        "release_target_id": meta.get("release_target_id"),
        "release_id": meta.get("release_id"),
        "manifest": meta.get("manifest") or {},
        "compose": meta.get("compose") or {},
        "deploy_outcome": meta.get("deploy_outcome"),
        "deployed_at": meta.get("deployed_at"),
    }


def _transcribe_audio(path: str, language_code: str) -> Dict[str, Any]:
    from google.cloud import speech  # type: ignore

    client = speech.SpeechClient()
    with open(path, "rb") as audio_file:
        content = audio_file.read()
    audio = speech.RecognitionAudio(content=content)
    config = speech.RecognitionConfig(
        language_code=language_code,
        enable_automatic_punctuation=True,
    )
    response = client.recognize(config=config, audio=audio)
    transcripts = []
    confidences = []
    for result in response.results:
        if result.alternatives:
            transcripts.append(result.alternatives[0].transcript)
            confidences.append(result.alternatives[0].confidence)
    transcript_text = "\n".join(transcripts).strip()
    confidence = sum(confidences) / len(confidences) if confidences else None
    return {
        "transcript_text": transcript_text,
        "confidence": confidence,
        "raw_response_json": {"results": [r.to_dict() for r in response.results]},
    }


def transcribe_voice_note(voice_note_id: str) -> None:
    voice_note = VoiceNote.objects.get(id=voice_note_id)
    if getattr(voice_note, "transcript", None):
        return
    voice_note.status = "transcribing"
    voice_note.error = ""
    voice_note.save(update_fields=["status", "error"])
    try:
        payload = _transcribe_audio(voice_note.audio_file.path, voice_note.language_code)
        VoiceTranscript.objects.update_or_create(
            voice_note=voice_note,
            defaults={
                "provider": "google_stt",
                "transcript_text": payload["transcript_text"],
                "confidence": payload.get("confidence"),
                "raw_response_json": payload.get("raw_response_json"),
            },
        )
        voice_note.status = "transcribed"
        voice_note.save(update_fields=["status"])
    except Exception as exc:
        voice_note.status = "failed"
        voice_note.error = str(exc)
        voice_note.save(update_fields=["status", "error"])


def _collect_transcripts(session: BlueprintDraftSession) -> List[str]:
    links = DraftSessionVoiceNote.objects.filter(draft_session=session).select_related("voice_note", "voice_note__transcript").order_by("ordering")
    transcripts = []
    for link in links:
        transcript = getattr(link.voice_note, "transcript", None)
        if transcript:
            transcripts.append(transcript.transcript_text)
    return transcripts


def _resolve_context(session: BlueprintDraftSession) -> Dict[str, Any]:
    defaults = list(
        ContextPack.objects.filter(scope="global", is_active=True, is_default=True).order_by("name")
    )
    selected = []
    if session.context_pack_ids:
        packs = ContextPack.objects.filter(id__in=session.context_pack_ids)
        pack_map = {str(pack.id): pack for pack in packs}
        for pack_id in session.context_pack_ids:
            if pack := pack_map.get(str(pack_id)):
                selected.append(pack)
    combined = []
    seen = set()
    for pack in defaults + selected:
        pack_id = str(pack.id)
        if pack_id in seen:
            continue
        seen.add(pack_id)
        combined.append(pack)
    sections = []
    refs = []
    for pack in combined:
        refs.append(
            {
                "id": str(pack.id),
                "name": pack.name,
                "scope": pack.scope,
                "version": pack.version,
                "is_active": pack.is_active,
            }
        )
        header = f"### ContextPack: {pack.name} ({pack.scope}) v{pack.version}"
        sections.append(f"{header}\n{pack.content_markdown}".strip())
    effective_context = "\n\n".join(sections).strip()
    digest = hashlib.sha256(effective_context.encode("utf-8")).hexdigest() if effective_context else ""
    preview = effective_context[:2000] if effective_context else ""
    return {
        "effective_context": effective_context,
        "refs": refs,
        "hash": digest,
        "preview": preview,
    }


def generate_blueprint_draft(session_id: str) -> None:
    session = BlueprintDraftSession.objects.get(id=session_id)
    session.status = "drafting"
    session.last_error = ""
    session.save(update_fields=["status", "last_error"])
    context = _resolve_context(session)
    session.context_pack_refs_json = context["refs"]
    session.effective_context_hash = context["hash"]
    session.effective_context_preview = context["preview"]
    session.save(
        update_fields=["context_pack_refs_json", "effective_context_hash", "effective_context_preview", "updated_at"]
    )
    transcripts = _collect_transcripts(session)
    combined = "\n".join(transcripts)
    draft = (
        _openai_generate_blueprint(combined, session.blueprint_kind, context["effective_context"])
        if combined
        else None
    )
    if not draft:
        draft = session.current_draft_json or {}
    errors = _validate_blueprint(draft, session.blueprint_kind) if draft else ["Draft generation failed"]
    session.current_draft_json = draft
    session.requirements_summary = combined[:2000]
    session.validation_errors_json = errors
    session.diff_summary = "Generated from transcript"
    session.status = "ready" if not errors else "ready_with_errors"
    session.updated_at = timezone.now()
    session.save(
        update_fields=[
            "current_draft_json",
            "requirements_summary",
            "validation_errors_json",
            "diff_summary",
            "status",
            "updated_at",
        ]
    )


def revise_blueprint_draft(session_id: str, instruction: str) -> None:
    session = BlueprintDraftSession.objects.get(id=session_id)
    session.status = "drafting"
    session.last_error = ""
    session.save(update_fields=["status", "last_error"])
    context = _resolve_context(session)
    session.context_pack_refs_json = context["refs"]
    session.effective_context_hash = context["hash"]
    session.effective_context_preview = context["preview"]
    session.save(
        update_fields=["context_pack_refs_json", "effective_context_hash", "effective_context_preview", "updated_at"]
    )
    base = session.requirements_summary or ""
    combined = (base + "\n" + instruction).strip()
    draft = (
        _openai_generate_blueprint(combined, session.blueprint_kind, context["effective_context"])
        or session.current_draft_json
        or {}
    )
    errors = _validate_blueprint(draft, session.blueprint_kind) if draft else ["Revision failed"]
    session.current_draft_json = draft
    session.requirements_summary = combined[:2000]
    session.validation_errors_json = errors
    session.diff_summary = f"Instruction: {instruction}"
    session.status = "ready" if not errors else "ready_with_errors"
    session.updated_at = timezone.now()
    session.save(
        update_fields=[
            "current_draft_json",
            "requirements_summary",
            "validation_errors_json",
            "diff_summary",
            "status",
            "updated_at",
        ]
    )
