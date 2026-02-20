import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from django.utils import timezone
from jsonschema import Draft202012Validator, RefResolver

from .models import (
    BlueprintDraftSession,
    ContextPack,
    DraftSessionRevision,
    DraftSessionVoiceNote,
    OpenAIConfig,
    Run,
    VoiceNote,
    VoiceTranscript,
)


def _record_draft_session_revision(session: BlueprintDraftSession, action: str, instruction: str = "") -> None:
    latest = (
        DraftSessionRevision.objects.filter(draft_session=session)
        .order_by("-revision_number")
        .first()
    )
    next_revision = (latest.revision_number if latest else 0) + 1
    DraftSessionRevision.objects.create(
        draft_session=session,
        revision_number=next_revision,
        action=action if action in {"generate", "revise", "save", "submit"} else "save",
        instruction=instruction or "",
        draft_json=session.current_draft_json,
        requirements_summary=session.requirements_summary or "",
        diff_summary=session.diff_summary or "",
        validation_errors_json=session.validation_errors_json or [],
        created_by=session.updated_by,
    )


def _contracts_root() -> str:
    return os.environ.get("XYNSEED_CONTRACTS_ROOT", "/xyn-contracts")


def _load_schema(name: str) -> Dict[str, Any]:
    path = os.path.join(_contracts_root(), "schemas", name)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_schema_store() -> Dict[str, Dict[str, Any]]:
    store: Dict[str, Dict[str, Any]] = {}
    schema_dir = os.path.join(_contracts_root(), "schemas")
    if not os.path.isdir(schema_dir):
        return store
    for filename in os.listdir(schema_dir):
        if not filename.endswith(".json"):
            continue
        try:
            schema = _load_schema(filename)
        except Exception:
            continue
        store[filename] = schema
        store[f"./{filename}"] = schema
        store[f"https://xyn.example/schemas/{filename}"] = schema
        schema_id = str(schema.get("$id") or "").strip()
        if schema_id:
            store[schema_id] = schema
    return store


def _schema_for_kind(kind: str) -> str:
    mapping = {
        "solution": "SolutionBlueprintSpec.schema.json",
        "module": "ModuleSpec.schema.json",
        "bundle": "BundleSpec.schema.json",
    }
    return mapping.get(kind, "SolutionBlueprintSpec.schema.json")


def _validate_blueprint(spec: Dict[str, Any], kind: str) -> List[str]:
    try:
        schema_name = _schema_for_kind(kind)
        schema = _load_schema(schema_name)
        resolver = RefResolver.from_schema(schema, store=_load_schema_store())
        validator = Draft202012Validator(schema, resolver=resolver)
        errors = []
        for error in sorted(validator.iter_errors(spec), key=lambda e: e.path):
            path = ".".join(str(p) for p in error.path) if error.path else "root"
            errors.append(f"{path}: {error.message}")
        return errors
    except Exception as exc:
        return [f"Schema validation unavailable: {exc}"]


def _extract_json_object(raw: str) -> Optional[Dict[str, Any]]:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        try:
            parsed = json.loads(fenced.group(1))
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            parsed = json.loads(text[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return None
    return None


def _normalize_generated_blueprint(spec: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    draft = dict(spec or {})
    kind = str(draft.get("kind") or "").strip()
    if kind == "SolutionBlueprintSpec":
        draft["kind"] = "SolutionBlueprint"
    metadata = draft.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("version", None)
    release_spec = draft.get("releaseSpec")
    if isinstance(release_spec, dict):
        components = release_spec.get("components")
        if isinstance(components, list):
            for component in components:
                if not isinstance(component, dict):
                    continue
                ports = component.get("ports")
                if isinstance(ports, list):
                    normalized_ports: List[Dict[str, Any]] = []
                    for port in ports:
                        normalized_port: Optional[Dict[str, Any]] = None
                        if isinstance(port, dict):
                            normalized_port = dict(port)
                            if "containerPort" not in normalized_port and "port" in normalized_port:
                                normalized_port["containerPort"] = normalized_port.get("port")
                            container_port = normalized_port.get("containerPort")
                            host_port = normalized_port.get("hostPort")
                            try:
                                if container_port is not None:
                                    normalized_port["containerPort"] = int(container_port)
                            except (TypeError, ValueError):
                                normalized_port.pop("containerPort", None)
                            try:
                                if host_port is not None:
                                    normalized_port["hostPort"] = int(host_port)
                            except (TypeError, ValueError):
                                normalized_port.pop("hostPort", None)
                            if isinstance(normalized_port.get("hostPort"), int) and normalized_port["hostPort"] <= 0:
                                normalized_port.pop("hostPort", None)
                            protocol = str(normalized_port.get("protocol") or "").strip().lower()
                            if protocol in {"tcp", "udp"}:
                                normalized_port["protocol"] = protocol
                            else:
                                normalized_port.pop("protocol", None)
                        elif isinstance(port, str):
                            value = port.strip().lower()
                            if value:
                                protocol = None
                                if "/" in value:
                                    value, proto = value.rsplit("/", 1)
                                    proto = proto.strip().lower()
                                    if proto in {"tcp", "udp"}:
                                        protocol = proto
                                parts = [part.strip() for part in value.split(":")]
                                if len(parts) == 1 and parts[0].isdigit():
                                    normalized_port = {"containerPort": int(parts[0])}
                                elif len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                                    normalized_port = {"hostPort": int(parts[0]), "containerPort": int(parts[1])}
                                elif len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
                                    normalized_port = {"hostPort": int(parts[1]), "containerPort": int(parts[2])}
                                if normalized_port is not None and protocol:
                                    normalized_port["protocol"] = protocol
                        if isinstance(normalized_port, dict) and isinstance(normalized_port.get("containerPort"), int):
                            normalized_port.pop("public", None)
                            normalized_port.pop("expose", None)
                            normalized_port.pop("hostname", None)
                            normalized_port.pop("http", None)
                            normalized_port.pop("https", None)
                            normalized_port.pop("tls", None)
                            normalized_port.pop("port", None)
                            normalized_ports.append(normalized_port)
                    component["ports"] = normalized_ports
                volume_mounts = component.get("volumeMounts")
                if isinstance(volume_mounts, list):
                    for mount in volume_mounts:
                        if not isinstance(mount, dict):
                            continue
                        if "volume" not in mount and "name" in mount:
                            mount["volume"] = mount.get("name")
                        mount.pop("name", None)
                # releaseSpec component schema allows either image or build, not both.
                has_build = isinstance(component.get("build"), dict) and bool(component.get("build"))
                has_image = isinstance(component.get("image"), str) and bool(component.get("image").strip())
                if has_build and has_image:
                    component.pop("image", None)
                resources = component.get("resources")
                if isinstance(resources, dict):
                    limits = resources.get("limits") if isinstance(resources.get("limits"), dict) else {}
                    requests = resources.get("requests") if isinstance(resources.get("requests"), dict) else {}
                    cpu = resources.get("cpu")
                    memory = resources.get("memory")
                    if not cpu:
                        cpu = limits.get("cpu") or requests.get("cpu")
                    if not memory:
                        memory = limits.get("memory") or requests.get("memory")
                    normalized_resources: Dict[str, Any] = {}
                    if cpu:
                        normalized_resources["cpu"] = str(cpu)
                    if memory:
                        normalized_resources["memory"] = str(memory)
                    if normalized_resources:
                        component["resources"] = normalized_resources
                    else:
                        component.pop("resources", None)
                env_entries = component.get("env")
                if isinstance(env_entries, list):
                    normalized_env: Dict[str, str] = {}
                    normalized_secret_refs = (
                        list(component.get("secretRefs")) if isinstance(component.get("secretRefs"), list) else []
                    )
                    for item in env_entries:
                        if not isinstance(item, dict):
                            continue
                        env_name = str(item.get("name") or "").strip()
                        if not env_name:
                            continue
                        env_value = item.get("value")
                        if env_value is not None:
                            normalized_env[env_name] = str(env_value)
                            continue
                        value_from = item.get("valueFrom")
                        if not isinstance(value_from, dict):
                            continue
                        secret_ref = value_from.get("secretRef")
                        if not isinstance(secret_ref, dict):
                            continue
                        secret_name = str(secret_ref.get("name") or "").strip()
                        secret_key = str(secret_ref.get("key") or "").strip()
                        if not secret_name:
                            continue
                        secret_payload: Dict[str, str] = {"name": secret_name}
                        if secret_key:
                            secret_payload["key"] = secret_key
                        secret_payload["targetEnv"] = env_name
                        normalized_secret_refs.append(secret_payload)
                    component["env"] = normalized_env
                    if normalized_secret_refs:
                        component["secretRefs"] = normalized_secret_refs
    return draft


def _merge_missing_fields(baseline: Any, candidate: Any) -> Any:
    if isinstance(baseline, dict) and isinstance(candidate, dict):
        merged = {k: _merge_missing_fields(baseline.get(k), v) for k, v in candidate.items()}
        for key, value in baseline.items():
            if key not in merged:
                merged[key] = value
        return merged
    if isinstance(baseline, list) and isinstance(candidate, list):
        if not baseline or not candidate:
            return candidate
        merged_list = list(candidate)
        for idx in range(min(len(baseline), len(merged_list))):
            merged_list[idx] = _merge_missing_fields(baseline[idx], merged_list[idx])
        if len(baseline) > len(merged_list):
            merged_list.extend(baseline[len(merged_list) :])
        return merged_list
    return candidate


def _schema_guardrails(kind: str) -> str:
    try:
        schema = _load_schema(_schema_for_kind(kind))
        required = schema.get("required") if isinstance(schema, dict) else []
        required_text = ", ".join(required) if isinstance(required, list) else ""
        release_required = ""
        release_spec = schema.get("properties", {}).get("releaseSpec") if isinstance(schema, dict) else None
        if isinstance(release_spec, dict):
            release_ref = str(release_spec.get("$ref") or "").replace("./", "")
            if release_ref:
                release_schema = _load_schema(release_ref)
                req = release_schema.get("required")
                if isinstance(req, list):
                    release_required = ", ".join(req)
        return (
            f"REQUIRED TOP-LEVEL KEYS: {required_text or 'apiVersion, kind, metadata, releaseSpec'}\n"
            f"RELEASE REQUIRED KEYS: {release_required or 'apiVersion, kind, metadata, backend, components'}\n"
            "CONSTRAINTS: preserve all existing keys unless instruction explicitly removes them; "
            "never drop required keys; keep identifiers stable unless explicitly renamed."
        )
    except Exception:
        return (
            "REQUIRED TOP-LEVEL KEYS: apiVersion, kind, metadata, releaseSpec\n"
            "RELEASE REQUIRED KEYS: apiVersion, kind, metadata, backend, components\n"
            "CONSTRAINTS: preserve existing structure and required fields."
        )


def draft_revision_patch_prompt(kind: str, context_text: str, guardrails: str) -> str:
    base = (
        "You are updating an existing blueprint draft JSON.\n"
        "Treat revision_instruction as a delta against baseline_draft_json.\n"
        "Apply a patch-style update: preserve unknown fields, preserve required fields, and only change what is needed.\n"
        "Do not remove fields unless explicitly requested.\n"
        "Return ONLY the full updated JSON object (no markdown, no prose)."
    )
    if kind == "module":
        base += "\nSchema target: ModuleSpec."
    elif kind == "bundle":
        base += "\nSchema target: BundleSpec."
    else:
        base += "\nSchema target: SolutionBlueprintSpec with valid ReleaseSpec."
    if context_text:
        return f"{context_text}\n\n{guardrails}\n\n{base}"
    return f"{guardrails}\n\n{base}"


def _openai_revise_blueprint(
    *,
    kind: str,
    context_text: str,
    baseline_draft_json: Dict[str, Any],
    revision_instruction: str,
    initial_prompt: str,
    prompt_sources: List[str],
    validation_errors: Optional[List[str]] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    config = OpenAIConfig.objects.first()
    if not config:
        return None, "OpenAI config is not configured."
    from openai import OpenAI  # type: ignore

    client = OpenAI(api_key=config.api_key)
    guardrails = _schema_guardrails(kind)
    system_prompt = draft_revision_patch_prompt(kind, context_text, guardrails)
    user_payload = {
        "baseline_draft_json": baseline_draft_json,
        "revision_instruction": revision_instruction,
        "initial_prompt": initial_prompt,
        "prompt_sources": prompt_sources,
    }
    if validation_errors:
        user_payload["validation_errors"] = validation_errors[:20]
    try:
        response = client.responses.create(
            model=config.default_model,
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload)},
            ],
        )
    except Exception as exc:
        return None, f"OpenAI revision request failed: {exc}"
    parsed = _extract_json_object(str(getattr(response, "output_text", "") or ""))
    if parsed is None:
        return None, "OpenAI revision response was not valid JSON."
    return parsed, None


def _openai_generate_blueprint(
    transcript: str, kind: str, context_text: str
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    config = OpenAIConfig.objects.first()
    if not config:
        return None, "OpenAI config is not configured."
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
            "You are generating JSON for Xyn and MUST return a SolutionBlueprintSpec-compatible object.\n"
            "Return ONLY a JSON object with no markdown, no prose, and no code fences.\n"
            "STRICT requirements:\n"
            "- Top-level required fields: apiVersion, kind, metadata, releaseSpec.\n"
            "- apiVersion must be exactly 'xyn.blueprint/v1'.\n"
            "- kind must be exactly 'Blueprint' or 'SolutionBlueprint'. NEVER 'SolutionBlueprintSpec'.\n"
            "- metadata must include only: name, namespace, labels (optional). Do NOT include metadata.version.\n"
            "- releaseSpec must be a valid Release object:\n"
            "  releaseSpec.apiVersion='xyn.seed/v1'\n"
            "  releaseSpec.kind='Release'\n"
            "  releaseSpec.metadata={name, namespace, labels?}\n"
            "  releaseSpec.backend={type:'compose'|'k8s', config?}\n"
            "  releaseSpec.components=[{name, image? or build{context,dockerfile?,imageName?,target?}, env?, ports?, volumeMounts?, dependsOn?, resources?}]\n"
            "- Do NOT include extra top-level keys.\n"
            "- If unknown, choose safe defaults and still produce a schema-valid object.\n"
            "Output JSON only."
        )
    if context_text:
        system_prompt = f"{context_text}\n\n{system_prompt}"
    try:
        response = client.responses.create(
            model=config.default_model,
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": transcript},
            ],
        )
    except Exception as exc:
        return None, f"OpenAI request failed: {exc}"
    output_text = str(getattr(response, "output_text", "") or "")
    parsed = _extract_json_object(output_text)
    if parsed is None:
        return None, "OpenAI response was not valid JSON."
    return parsed, None


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
        "release_uuid": meta.get("release_uuid"),
        "release_version": meta.get("release_version"),
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
    session.context_resolved_at = timezone.now()
    session.save(
        update_fields=[
            "context_pack_refs_json",
            "effective_context_hash",
            "effective_context_preview",
            "context_resolved_at",
            "updated_at",
        ]
    )
    transcripts = _collect_transcripts(session)
    source_artifacts = session.source_artifacts or []
    source_texts: List[str] = []
    for artifact in source_artifacts:
        if not isinstance(artifact, dict):
            continue
        artifact_type = str(artifact.get("type", "")).strip().lower()
        if artifact_type not in {"text", "audio_transcript"}:
            continue
        content = str(artifact.get("content", "")).strip()
        if content:
            source_texts.append(content)
    ordered_inputs: List[str] = []
    for text in [str(session.initial_prompt or "").strip(), *source_texts, *transcripts]:
        if text and text not in ordered_inputs:
            ordered_inputs.append(text)
    combined = "\n\n".join(ordered_inputs).strip()
    generation_error = None
    draft = None
    if combined:
        draft, generation_error = _openai_generate_blueprint(combined, session.blueprint_kind, context["effective_context"])
    else:
        generation_error = "No prompt input provided."
    if not draft:
        draft = session.current_draft_json or {}
    draft = _normalize_generated_blueprint(draft)
    errors = _validate_blueprint(draft, session.blueprint_kind) if draft else []
    if generation_error:
        errors = [generation_error, *errors] if generation_error not in errors else errors
    if not errors and not draft:
        errors = ["Draft generation failed"]
    session.current_draft_json = draft
    session.requirements_summary = combined[:2000]
    session.validation_errors_json = errors
    session.diff_summary = "Generated from prompt inputs"
    session.status = "ready" if not errors else "ready_with_errors"
    if draft and not session.initial_prompt_locked and session.initial_prompt.strip():
        session.initial_prompt_locked = True
    session.updated_at = timezone.now()
    session.save(
        update_fields=[
            "current_draft_json",
            "requirements_summary",
            "validation_errors_json",
            "diff_summary",
            "status",
            "initial_prompt_locked",
            "updated_at",
        ]
    )
    _record_draft_session_revision(session, action="generate")


def revise_blueprint_draft(session_id: str, instruction: str) -> None:
    session = BlueprintDraftSession.objects.get(id=session_id)
    session.status = "drafting"
    session.last_error = ""
    session.save(update_fields=["status", "last_error"])
    context = _resolve_context(session)
    session.context_pack_refs_json = context["refs"]
    session.effective_context_hash = context["hash"]
    session.effective_context_preview = context["preview"]
    session.context_resolved_at = timezone.now()
    session.save(
        update_fields=[
            "context_pack_refs_json",
            "effective_context_hash",
            "effective_context_preview",
            "context_resolved_at",
            "updated_at",
        ]
    )
    baseline = session.current_draft_json or {}
    prompt_sources: List[str] = []
    for artifact in session.source_artifacts or []:
        if not isinstance(artifact, dict):
            continue
        artifact_type = str(artifact.get("type", "")).strip().lower()
        if artifact_type not in {"text", "audio_transcript"}:
            continue
        content = str(artifact.get("content", "")).strip()
        if content:
            prompt_sources.append(content)
    generation_error = None
    draft, generation_error = _openai_revise_blueprint(
        kind=session.blueprint_kind,
        context_text=context["effective_context"],
        baseline_draft_json=baseline,
        revision_instruction=instruction,
        initial_prompt=session.initial_prompt or "",
        prompt_sources=prompt_sources,
    )
    if not draft:
        draft = baseline
    draft = _normalize_generated_blueprint(draft)
    draft = _merge_missing_fields(baseline, draft) if isinstance(draft, dict) else draft
    errors = _validate_blueprint(draft, session.blueprint_kind) if draft else ["Revision failed"]
    if errors:
        retry_draft, retry_error = _openai_revise_blueprint(
            kind=session.blueprint_kind,
            context_text=context["effective_context"],
            baseline_draft_json=baseline,
            revision_instruction=instruction,
            initial_prompt=session.initial_prompt or "",
            prompt_sources=prompt_sources,
            validation_errors=errors,
        )
        if retry_draft:
            retry_draft = _normalize_generated_blueprint(retry_draft)
            retry_draft = _merge_missing_fields(baseline, retry_draft) if isinstance(retry_draft, dict) else retry_draft
            retry_errors = _validate_blueprint(retry_draft, session.blueprint_kind)
            if not retry_errors:
                draft = retry_draft
                errors = []
        if retry_error and retry_error not in errors:
            errors = [retry_error, *errors]
    if generation_error and generation_error not in errors:
        errors = [generation_error, *errors]
    session.current_draft_json = draft
    session.requirements_summary = (session.initial_prompt or "")[:2000]
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
    _record_draft_session_revision(session, action="revise", instruction=instruction)
