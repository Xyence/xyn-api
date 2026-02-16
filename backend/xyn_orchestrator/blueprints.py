import hashlib
import json
import logging
import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Callable
from pathlib import Path
from typing import Any, Dict, List, Optional

from django.db import models
from django.db import transaction
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.conf import settings
from django.utils.text import slugify
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from jsonschema import Draft202012Validator, RefResolver

from .services import (
    generate_blueprint_draft,
    revise_blueprint_draft,
    transcribe_voice_note,
)
from .models import (
    Blueprint,
    BlueprintDraftSession,
    DraftSessionRevision,
    BlueprintInstance,
    BlueprintRevision,
    Bundle,
    Capability,
    ContextPack,
    DevTask,
    DraftSessionVoiceNote,
    Environment,
    Module,
    Registry,
    ReleasePlan,
    ReleasePlanDeployState,
    ReleasePlanDeployment,
    Deployment,
    Release,
    ReleaseTarget,
    ProvisionedInstance,
    Run,
    RunCommandExecution,
    RunArtifact,
    VoiceNote,
    VoiceTranscript,
)
from .services import get_release_target_deploy_state
from .worker_tasks import _ssm_fetch_runtime_marker
from .deployments import (
    compute_idempotency_base,
    execute_release_plan_deploy,
    infer_app_id,
    load_release_plan_json,
    maybe_trigger_rollback,
)

_executor = ThreadPoolExecutor(max_workers=2)
logger = logging.getLogger(__name__)


def _record_draft_session_revision(
    session: BlueprintDraftSession,
    action: str,
    instruction: str = "",
    created_by=None,
) -> None:
    latest = (
        DraftSessionRevision.objects.filter(draft_session=session)
        .order_by("-revision_number")
        .first()
    )
    next_revision = (latest.revision_number if latest else 0) + 1
    return DraftSessionRevision.objects.create(
        draft_session=session,
        revision_number=next_revision,
        action=action if action in {"generate", "revise", "save", "snapshot", "submit"} else "save",
        instruction=instruction or "",
        draft_json=session.current_draft_json,
        requirements_summary=session.requirements_summary or "",
        diff_summary=session.diff_summary or "",
        validation_errors_json=session.validation_errors_json or [],
        created_by=created_by,
    )


def _is_draft_context_stale(session: BlueprintDraftSession) -> bool:
    selected_ids = {
        str(pack_id)
        for pack_id in (session.selected_context_pack_ids or session.context_pack_ids or [])
        if str(pack_id).strip()
    }
    refs = session.context_pack_refs_json if isinstance(session.context_pack_refs_json, list) else []
    ref_ids = {
        str(ref.get("id"))
        for ref in refs
        if isinstance(ref, dict) and str(ref.get("id", "")).strip()
    }
    if not (session.effective_context_hash or "").strip():
        return True
    if selected_ids and not ref_ids:
        return True
    if selected_ids and ref_ids and not selected_ids.issubset(ref_ids):
        return True
    return False


def _snapshot_draft_session(
    session: BlueprintDraftSession,
    created_by=None,
    note: str = "",
    action: str = "snapshot",
) -> DraftSessionRevision:
    snapshot_note = (note or "").strip() or "manual snapshot"
    return _record_draft_session_revision(
        session,
        action=action,
        instruction=snapshot_note,
        created_by=created_by,
    )


def _write_run_artifact(run: Run, filename: str, content: str | dict | list, kind: str) -> RunArtifact:
    artifacts_root = os.path.join(settings.MEDIA_ROOT, "run_artifacts", str(run.id))
    os.makedirs(artifacts_root, exist_ok=True)
    file_path = os.path.join(artifacts_root, filename)
    if isinstance(content, (dict, list)):
        serialized = json.dumps(content, indent=2)
    else:
        serialized = content
    with open(file_path, "w", encoding="utf-8") as handle:
        handle.write(serialized)
    url = f"{settings.MEDIA_URL.rstrip('/')}/run_artifacts/{run.id}/{filename}"
    return RunArtifact.objects.create(run=run, name=filename, kind=kind, url=url)


def _read_run_artifact_json(artifact: RunArtifact) -> Optional[Dict[str, Any]]:
    if not artifact.url or not artifact.url.startswith("/media/"):
        return None
    file_path = os.path.join(settings.MEDIA_ROOT, artifact.url.replace("/media/", ""))
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError:
        return None


def _async_mode() -> str:
    mode = os.environ.get("XYENCE_ASYNC_JOBS_MODE", "").strip().lower()
    if mode:
        return mode
    return "inprocess" if os.environ.get("DJANGO_DEBUG", "false").lower() == "true" else "redis"


def _require_staff(request: HttpRequest) -> Optional[JsonResponse]:
    if not request.user.is_authenticated or not request.user.is_staff:
        return JsonResponse({"error": "Staff access required"}, status=403)
    return None


def _require_internal_token(request: HttpRequest) -> Optional[JsonResponse]:
    expected = os.environ.get("XYENCE_INTERNAL_TOKEN", "").strip()
    if not expected:
        return JsonResponse({"error": "Internal token not configured"}, status=500)
    provided = request.headers.get("X-Internal-Token", "").strip()
    if not provided:
        auth_header = request.headers.get("Authorization", "").strip()
        if auth_header.lower().startswith("bearer "):
            provided = auth_header.split(" ", 1)[1].strip()
    if provided != expected:
        return JsonResponse({"error": "Unauthorized"}, status=401)
    return None


def _enqueue_job(func_path: str, *args) -> str:
    import redis
    from rq import Queue

    redis_url = os.environ.get("XYENCE_JOBS_REDIS_URL", "redis://redis:6379/0")
    queue = Queue("default", connection=redis.Redis.from_url(redis_url))
    job = queue.enqueue(func_path, *args, job_timeout=900)
    return job.id

def _xynseed_request(method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    import requests

    base_url = os.environ.get("XYNSEED_BASE_URL", "http://localhost:8001/api/v1").rstrip("/")
    token = os.environ.get("XYNSEED_API_TOKEN", "").strip()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.request(
        method=method,
        url=f"{base_url}{path}",
        json=payload,
        headers=headers,
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def _contracts_root() -> Optional[Path]:
    if env_root := os.environ.get("XYNSEED_CONTRACTS_ROOT", "").strip():
        candidate = Path(env_root)
        if candidate.exists():
            return candidate
    root = Path(__file__).resolve()
    for parent in root.parents:
        candidate = parent / "xyn-contracts"
        if candidate.exists():
            return candidate
    return None


def _load_schema(schema_name: str) -> Dict[str, Any]:
    root = _contracts_root()
    if not root:
        raise FileNotFoundError("xyn-contracts not found")
    schema_path = root / "schemas" / schema_name
    return json.loads(schema_path.read_text())


def _schema_for_kind(kind: str) -> str:
    mapping = {
        "solution": "SolutionBlueprintSpec.schema.json",
        "module": "ModuleSpec.schema.json",
        "bundle": "BundleSpec.schema.json",
    }
    return mapping.get(kind, "SolutionBlueprintSpec.schema.json")


def _load_schema_store() -> Dict[str, Dict[str, Any]]:
    root = _contracts_root()
    if not root:
        return {}
    schema_dir = root / "schemas"
    store: Dict[str, Dict[str, Any]] = {}
    if not schema_dir.exists():
        return store
    for schema_path in schema_dir.glob("*.json"):
        try:
            schema = json.loads(schema_path.read_text())
        except Exception:
            continue
        filename = schema_path.name
        store[filename] = schema
        store[f"./{filename}"] = schema
        store[f"https://xyn.example/schemas/{filename}"] = schema
        schema_id = str(schema.get("$id") or "").strip()
        if schema_id:
            store[schema_id] = schema
    return store


def _validate_blueprint_spec(spec: Dict[str, Any], kind: str = "solution") -> List[str]:
    schema = _load_schema(_schema_for_kind(kind))
    resolver = RefResolver.from_schema(schema, store=_load_schema_store())
    validator = Draft202012Validator(schema, resolver=resolver)
    errors = []
    for error in sorted(validator.iter_errors(spec), key=lambda e: e.path):
        path = ".".join(str(p) for p in error.path) if error.path else "root"
        errors.append(f"{path}: {error.message}")
    return errors


_SECRET_REF_INTERPOLATION_RE = re.compile(r"(?<!\$)\$\{secretRef:[^}]+\}")
_NAMESPACE_PROJECT_SEGMENT_RE = re.compile(r"[^a-z0-9_-]+")


def _sanitize_release_namespace(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return raw
    normalized = raw.replace(".", "-")
    normalized = _NAMESPACE_PROJECT_SEGMENT_RE.sub("-", normalized)
    normalized = normalized.strip("-_")
    return normalized or "core"


def _sanitize_release_spec_for_xynseed(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized = {k: _sanitize_release_spec_for_xynseed(v) for k, v in value.items()}
        metadata = sanitized.get("metadata")
        if isinstance(metadata, dict):
            namespace = metadata.get("namespace")
            if isinstance(namespace, str):
                metadata["namespace"] = _sanitize_release_namespace(namespace)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_release_spec_for_xynseed(item) for item in value]
    if isinstance(value, str):
        return _SECRET_REF_INTERPOLATION_RE.sub(
            lambda match: "$" + match.group(0),
            value,
        )
    return value


def _load_runner_release_spec() -> Optional[Dict[str, Any]]:
    root = _contracts_root()
    if not root:
        return None
    fixture = root / "fixtures" / "runner.release.json"
    if not fixture.exists():
        return None
    return json.loads(fixture.read_text())


def _has_release_spec_hints(spec: Dict[str, Any], blueprint: Blueprint) -> bool:
    if blueprint.spec_text or blueprint.metadata_json:
        return True
    metadata = spec.get("metadata") or {}
    if metadata.get("labels") or metadata.get("name"):
        return True
    for key in ("requirements", "modules_required", "stack", "services", "ingress"):
        if key in spec:
            return True
    return False


def _default_release_spec_from_hints(spec: Dict[str, Any], blueprint: Blueprint) -> Optional[Dict[str, Any]]:
    release_spec = _load_runner_release_spec()
    if release_spec:
        return release_spec
    metadata = spec.get("metadata") or {}
    name = metadata.get("name") or blueprint.name or "blueprint"
    namespace = metadata.get("namespace") or blueprint.namespace or "core"
    return {
        "name": f"{namespace}.{name}",
        "version": "0.1.0",
        "modules": [
            {
                "fqn": "core.app-web-stack",
                "version": "0.1.0",
            }
        ],
    }


def _generate_blueprint_spec(session: BlueprintDraftSession, transcripts: List[str]) -> Dict[str, Any]:
    release_spec = _load_runner_release_spec()
    name = slugify(session.name) or "blueprint"
    spec = {
        "apiVersion": "xyn.blueprint/v1",
        "kind": "Blueprint",
        "metadata": {
            "name": name,
            "namespace": "core",
            "labels": {"source": "voice"}
        },
        "description": session.requirements_summary or "",
        "releaseSpec": release_spec or {}
    }
    if transcripts:
        spec["requirements"] = transcripts
    return spec


def _sha256_text(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def _split_prompt_lines(text: str) -> List[str]:
    lines: List[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        lines.append(line)
    return lines


def _append_unique(values: List[str], item: str) -> None:
    cleaned = (item or "").strip()
    if not cleaned:
        return
    lowered = cleaned.lower()
    if any(existing.lower() == lowered for existing in values):
        return
    values.append(cleaned)


def _extract_requirement_bullets(prompt_text: str, transcripts_text: str) -> Dict[str, List[str]]:
    combined = "\n".join(part for part in [prompt_text, transcripts_text] if part).strip()
    lines = _split_prompt_lines(combined)
    sections: Dict[str, List[str]] = {
        "functional": [],
        "ui": [],
        "dataModel": [],
        "operational": [],
        "definitionOfDone": [],
    }
    active_section: Optional[str] = None
    for line in lines:
        lower = line.lower()
        if "definition of done" in lower or "acceptance" in lower:
            active_section = "definitionOfDone"
            continue
        if "data model" in lower:
            active_section = "dataModel"
            continue
        if "frontend" in lower or "ui" in lower:
            active_section = "ui"
            continue
        if "backend" in lower or "api" in lower:
            active_section = "functional"
            continue
        if any(token in lower for token in ["operational", "deployment", "migrations", "logging", "secret", "idempotent"]):
            active_section = "operational"
            continue
        if line.startswith(("-", "*")):
            bullet = line[1:].strip()
            if active_section:
                _append_unique(sections[active_section], bullet)
            continue
        if active_section and len(line) < 180:
            _append_unique(sections[active_section], line)

    prompt_lower = combined.lower()
    if any(token in prompt_lower for token in ["create", "list", "delete", "crud"]):
        _append_unique(sections["functional"], "Implement create/list/delete API endpoints for the primary entity.")
    if "health endpoint" in prompt_lower or "/health" in prompt_lower or "health check" in prompt_lower:
        _append_unique(sections["functional"], "Expose a health endpoint for deployment verification.")
    if "subscriber notes" in prompt_lower:
        _append_unique(sections["ui"], "Render header titled 'Subscriber Notes - Dev Demo'.")
        _append_unique(sections["ui"], "Show a table listing notes from the API.")
        _append_unique(sections["ui"], "Provide an add-note form.")
        _append_unique(sections["ui"], "Support deleting notes from the table.")
        _append_unique(sections["dataModel"], "id (auto-generated)")
        _append_unique(sections["dataModel"], "subscriber_id (string)")
        _append_unique(sections["dataModel"], "note_text (string)")
        _append_unique(sections["dataModel"], "created_at (timestamp)")
        _append_unique(sections["functional"], "Implement create/list/delete endpoints for subscriber notes.")
        _append_unique(sections["functional"], "Provide API health endpoint.")
    if any(token in prompt_lower for token in ["secret", "config", "logging", "migration", "idempotent"]):
        _append_unique(sections["operational"], "Configure secrets and runtime config through environment/secret refs.")
        _append_unique(sections["operational"], "Enable structured logging for API and worker flows.")
        _append_unique(sections["operational"], "Run migrations safely and idempotently on deploy.")
    if "https://josh.xyence.io" in prompt_lower:
        _append_unique(
            sections["definitionOfDone"],
            "Deploy at https://josh.xyence.io and verify app is reachable with expected UI and APIs.",
        )

    return sections


def _build_draft_intent(session: BlueprintDraftSession, draft: Dict[str, Any]) -> Dict[str, Any]:
    prompt_text = session.initial_prompt or ""
    prompt_created_at = (session.created_at or timezone.now()).isoformat()
    artifacts = session.source_artifacts if isinstance(session.source_artifacts, list) else []
    transcripts: List[Dict[str, Any]] = []
    transcript_text_parts: List[str] = []
    for idx, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            continue
        if str(artifact.get("type") or "").strip().lower() != "audio_transcript":
            continue
        transcript_text = str(artifact.get("content") or "").strip()
        meta = artifact.get("meta") if isinstance(artifact.get("meta"), dict) else {}
        transcript_id = (
            str(meta.get("id") or meta.get("voice_note_id") or meta.get("transcript_id") or "").strip()
            or f"transcript-{idx + 1}"
        )
        entry: Dict[str, Any] = {"id": transcript_id}
        ref = str(meta.get("ref") or meta.get("url") or "").strip()
        if ref:
            entry["ref"] = ref
        if transcript_text:
            entry["text"] = transcript_text
            entry["sha256"] = _sha256_text(transcript_text)
            transcript_text_parts.append(transcript_text)
        if created_at := meta.get("created_at"):
            entry["createdAt"] = str(created_at)
        transcripts.append(entry)

    transcript_text = "\n\n".join(transcript_text_parts)
    requirements_sections = _extract_requirement_bullets(prompt_text, transcript_text)
    summary = (session.requirements_summary or "").strip()
    if not summary:
        summary_source = prompt_text or transcript_text or "Blueprint generated from draft session."
        summary = summary_source[:800]

    intent: Dict[str, Any] = {
        "sourceDraftSessionId": str(session.id),
        "createdFrom": {"type": "draft", "id": str(session.id)},
        "prompt": {
            "text": prompt_text,
            "sha256": _sha256_text(prompt_text),
            "createdAt": prompt_created_at,
        },
        "requirements": {
            "summary": summary,
            "functional": requirements_sections["functional"],
            "ui": requirements_sections["ui"],
            "dataModel": requirements_sections["dataModel"],
            "operational": requirements_sections["operational"],
            "definitionOfDone": requirements_sections["definitionOfDone"],
        },
    }
    if transcripts:
        intent["transcripts"] = transcripts
    intent["codegen"] = {"layout": {"apiPath": "services/api", "webPath": "services/web"}}
    return intent


def _extract_blueprint_intent(blueprint: Blueprint) -> Dict[str, Any]:
    spec_json: Optional[Dict[str, Any]] = None
    if blueprint.spec_text:
        try:
            parsed = json.loads(blueprint.spec_text)
            if isinstance(parsed, dict):
                spec_json = parsed
        except json.JSONDecodeError:
            spec_json = None
    if spec_json is None:
        latest = blueprint.revisions.order_by("-revision").first()
        if latest and isinstance(latest.spec_json, dict):
            spec_json = latest.spec_json
    if not isinstance(spec_json, dict):
        return {}
    intent = spec_json.get("intent")
    return intent if isinstance(intent, dict) else {}


def _apply_intent_context_to_work_items(
    work_items: List[Dict[str, Any]],
    intent_requirements: Dict[str, Any],
    intent_prompt: str,
) -> None:
    if not work_items:
        return
    summary = str(intent_requirements.get("summary") or "").strip()
    bullets: List[str] = []
    for key in ("functional", "ui", "dataModel", "operational", "definitionOfDone"):
        values = intent_requirements.get(key) or []
        if isinstance(values, list):
            for value in values:
                cleaned = str(value).strip()
                if cleaned:
                    _append_unique(bullets, cleaned)
    for item in work_items:
        inputs = item.get("inputs")
        if not isinstance(inputs, dict):
            inputs = {}
            item["inputs"] = inputs
        context = inputs.get("context")
        if not isinstance(context, list):
            context = []
        if "blueprint.intent.requirements" not in context:
            context.append("blueprint.intent.requirements")
        inputs["context"] = context
    first = work_items[0]
    if summary:
        first["description"] = summary
    elif intent_prompt:
        first["description"] = intent_prompt[:240]
    if bullets:
        criteria = first.get("acceptance_criteria")
        if not isinstance(criteria, list):
            criteria = []
        existing = {str(entry).strip().lower() for entry in criteria}
        for bullet in bullets[:8]:
            lowered = bullet.lower()
            if lowered in existing:
                continue
            criteria.append(bullet)
            existing.add(lowered)
        first["acceptance_criteria"] = criteria


def _select_context_packs_deterministic(
    purpose: str,
    namespace: Optional[str],
    project_key: Optional[str],
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    task_type: Optional[str] = None,
) -> List[ContextPack]:
    allowed_purposes = {purpose, "any"}
    packs = ContextPack.objects.filter(is_active=True, purpose__in=allowed_purposes)
    if not namespace and not project_key:
        packs = packs.filter(Q(scope="global") | Q(is_default=True))
    packs = packs.order_by("name", "id")
    selected = []
    for pack in packs:
        if _context_pack_applies(
            pack,
            purpose,
            namespace,
            project_key,
            action=action,
            entity_type=entity_type,
            task_type=task_type,
        ):
            selected.append(pack)
    return selected


def _resolve_context_packs(
    session: Optional[BlueprintDraftSession],
    selected_ids: Optional[List[str]] = None,
    purpose: str = "any",
    namespace: Optional[str] = None,
    project_key: Optional[str] = None,
    action: Optional[str] = None,
) -> Dict[str, Any]:
    ids = selected_ids if selected_ids is not None else ((session.context_pack_ids or []) if session else [])
    defaults = _select_context_packs_deterministic(purpose, namespace, project_key, action=action)
    selected = []
    if ids:
        packs = ContextPack.objects.filter(id__in=ids)
        pack_map = {str(pack.id): pack for pack in packs}
        for pack_id in ids:
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
        if not _context_pack_applies(pack, purpose, namespace, project_key, action):
            continue
        content_hash = hashlib.sha256(pack.content_markdown.encode("utf-8")).hexdigest()
        refs.append(
            {
                "id": str(pack.id),
                "name": pack.name,
                "purpose": pack.purpose,
                "scope": pack.scope,
                "version": pack.version,
                "content_hash": content_hash,
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


def _resolve_context_pack_list(packs: List[ContextPack]) -> Dict[str, Any]:
    sections = []
    refs = []
    for pack in packs:
        content_hash = hashlib.sha256(pack.content_markdown.encode("utf-8")).hexdigest()
        refs.append(
            {
                "id": str(pack.id),
                "name": pack.name,
                "purpose": pack.purpose,
                "scope": pack.scope,
                "version": pack.version,
                "content_hash": content_hash,
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


def _context_pack_applies(
    pack: ContextPack,
    purpose: str,
    namespace: Optional[str],
    project_key: Optional[str],
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    task_type: Optional[str] = None,
) -> bool:
    if not pack.is_active:
        return False
    if pack.purpose not in {"any", purpose}:
        return False
    if pack.scope == "namespace" and namespace and pack.namespace != namespace:
        return False
    if pack.scope == "project" and project_key and pack.project_key != project_key:
        return False
    if pack.scope == "namespace" and not namespace:
        return False
    if pack.scope == "project" and not project_key:
        return False
    applies = pack.applies_to_json or {}
    if isinstance(applies, dict):
        actions = applies.get("actions")
        if action and actions and action not in actions and "any" not in actions:
            return False
        entity_types = applies.get("entity_types")
        if entity_type and entity_types and entity_type not in entity_types and "any" not in entity_types:
            return False
        task_types = applies.get("task_types")
        if task_type and task_types and task_type not in task_types and "any" not in task_types:
            return False
        purposes = applies.get("purposes")
        if purposes and purpose not in purposes and "any" not in purposes:
            return False
        namespaces = applies.get("namespaces")
        if namespaces and namespace and namespace not in namespaces:
            return False
        projects = applies.get("projects")
        if projects and project_key and project_key not in projects:
            return False
        scopes = applies.get("scopes")
        if scopes and pack.scope not in scopes:
            return False
    return True


def _build_context_artifacts(run: Run, resolved: Dict[str, Any]) -> None:
    manifest = {
        "context_hash": resolved.get("hash"),
        "packs": resolved.get("refs", []),
    }
    _write_run_artifact(run, "context_compiled.md", resolved.get("effective_context", ""), "context")
    _write_run_artifact(run, "context_manifest.json", manifest, "context")


def _write_run_summary(run: Run) -> None:
    def _dt(value: Optional[timezone.datetime]) -> Optional[str]:
        if not value:
            return None
        return value.isoformat()

    summary = {
        "id": str(run.id),
        "entity_type": run.entity_type,
        "entity_id": str(run.entity_id),
        "status": run.status,
        "summary": run.summary,
        "error": run.error,
        "started_at": _dt(run.started_at),
        "finished_at": _dt(run.finished_at),
        "created_at": _dt(run.created_at),
    }
    _write_run_artifact(run, "run_summary.json", summary, "summary")


def _load_runtime_schema(name: str) -> Dict[str, Any]:
    base_dir = Path(__file__).resolve().parents[1]
    path = base_dir / "schemas" / name
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _validate_schema(payload: Dict[str, Any], name: str) -> List[str]:
    schema = _load_runtime_schema(name)
    validator = Draft202012Validator(schema)
    errors = []
    for error in validator.iter_errors(payload):
        path = ".".join(str(p) for p in error.path) if error.path else "root"
        errors.append(f"{path}: {error.message}")
    return errors


def _release_target_payload(target: ReleaseTarget) -> Dict[str, Any]:
    now = timezone.now().isoformat()
    dns = target.dns_json or {}
    runtime = target.runtime_json or {}
    tls = target.tls_json or {}
    ingress = (target.config_json or {}).get("ingress") or {}
    env = target.env_json or {}
    secret_refs = target.secret_refs_json or []
    payload = {
        "schema_version": "release_target.v1",
        "id": str(target.id),
        "blueprint_id": str(target.blueprint_id),
        "name": target.name,
        "environment": target.environment or "",
        "environment_id": (
            str(target.target_instance.environment_id)
            if target.target_instance and target.target_instance.environment_id
            else ""
        ),
        "target_instance_id": (
            str(target.target_instance_id)
            if target.target_instance_id
            else (target.target_instance_ref or "")
        ),
        "fqdn": target.fqdn,
        "dns": dns,
        "runtime": runtime,
        "tls": tls,
        "ingress": ingress,
        "env": env,
        "secret_refs": secret_refs,
        "created_at": target.created_at.isoformat() if target.created_at else now,
        "updated_at": target.updated_at.isoformat() if target.updated_at else now,
    }
    return payload


def _select_release_target_for_blueprint(
    blueprint: Blueprint,
    release_target_id: Optional[str] = None,
) -> Optional[ReleaseTarget]:
    qs = ReleaseTarget.objects.filter(blueprint=blueprint).order_by("-created_at")
    if release_target_id:
        try:
            return qs.filter(id=release_target_id).first()
        except (ValueError, TypeError):
            return None
    metadata = blueprint.metadata_json or {}
    default_id = metadata.get("default_release_target_id")
    if default_id:
        try:
            target = qs.filter(id=default_id).first()
            if target:
                return target
        except (ValueError, TypeError):
            pass
    return qs.first()


def _enqueue_release_build(release: Release, user) -> Dict[str, Any]:
    blueprint = release.blueprint
    if not blueprint:
        return {"ok": False, "error": "release missing blueprint"}
    release_target = _select_release_target_for_blueprint(blueprint)
    release_payload = _release_target_payload(release_target) if release_target else None
    run = Run.objects.create(
        entity_type="blueprint",
        entity_id=blueprint.id,
        status="running",
        summary=f"Build artifacts for release {release.version}",
        log_text="Preparing release build run\n",
        metadata_json={
            "release_id": str(release.id),
            "release_version": release.version,
            "release_target_id": str(release_target.id) if release_target else "",
        },
        created_by=user,
    )
    _write_run_artifact(run, "blueprint_metadata.json", blueprint.metadata_json or {}, "blueprint")
    if release_payload:
        _write_run_artifact(run, "release_target.json", release_payload, "release_target")
    module_catalog = _build_module_catalog()
    _write_run_artifact(run, "module_catalog.v1.json", module_catalog, "module_catalog")
    run_history_summary = _build_run_history_summary(blueprint, release_payload)
    _write_run_artifact(run, "run_history_summary.v1.json", run_history_summary, "run_history_summary")
    implementation_plan = _generate_implementation_plan(
        blueprint,
        module_catalog=module_catalog,
        run_history_summary=run_history_summary,
        release_target=release_payload,
    )
    build_items = [
        item
        for item in implementation_plan.get("work_items", [])
        if item.get("id") in {"build.publish_images.container", "build.publish_images.components"}
    ]
    if not build_items:
        run.status = "succeeded"
        run.finished_at = timezone.now()
        run.log_text = (run.log_text or "") + "No build work items detected for release.\n"
        run.save(update_fields=["status", "finished_at", "log_text", "updated_at"])
        _write_run_summary(run)
        return {"ok": True, "run_id": str(run.id), "queued": False}
    for item in build_items:
        config = item.setdefault("config", {})
        config["release_uuid"] = str(release.id)
        config["release_version"] = release.version
    implementation_plan["work_items"] = build_items
    _write_run_artifact(run, "implementation_plan.json", implementation_plan, "implementation_plan")
    _queue_dev_tasks_for_plan(
        blueprint=blueprint,
        run=run,
        plan=implementation_plan,
        namespace=blueprint.namespace,
        project_key=f"{blueprint.namespace}.{blueprint.name}",
        release_target=release_payload,
        enqueue_jobs=True,
    )
    run.status = "succeeded"
    run.finished_at = timezone.now()
    run.log_text = (run.log_text or "") + "Queued release build tasks\n"
    run.save(update_fields=["status", "finished_at", "log_text", "updated_at"])
    _write_run_summary(run)
    return {"ok": True, "run_id": str(run.id), "queued": True}


def _default_repo_targets() -> List[Dict[str, Any]]:
    return [
        {
            "name": "xyn-api",
            "url": "https://github.com/Xyence/xyn-api",
            "ref": "main",
            "path_root": "apps/ems-api",
            "auth": "https_token",
            "allow_write": True,
        },
        {
            "name": "xyn-ui",
            "url": "https://github.com/Xyence/xyn-ui",
            "ref": "main",
            "path_root": "apps/ems-ui",
            "auth": "https_token",
            "allow_write": True,
        },
    ]


def _normalize_repo_target_entry(target: Dict[str, Any]) -> Dict[str, Any]:
    default_map = {entry["name"]: entry for entry in _default_repo_targets()}
    name = str(target.get("name") or "").strip()
    base = default_map.get(name, {})
    url = str(target.get("url") or base.get("url") or "").strip()
    ref = str(target.get("ref") or base.get("ref") or "main").strip() or "main"
    path_root = str(target.get("path_root") or base.get("path_root") or ".").strip() or "."
    auth = str(target.get("auth") or base.get("auth") or "https_token").strip() or "https_token"
    allow_write_raw = target.get("allow_write")
    if allow_write_raw is None:
        allow_write_raw = base.get("allow_write")
    allow_write = bool(allow_write_raw) if allow_write_raw is not None else False
    return {
        "name": name,
        "url": url,
        "ref": ref,
        "path_root": path_root,
        "auth": auth,
        "allow_write": allow_write,
    }


def _ensure_repo_target_complete(target: Dict[str, Any], context: str = "repo target") -> Dict[str, Any]:
    missing = [field for field in ("name", "url", "ref", "path_root", "auth") if not str(target.get(field) or "").strip()]
    if missing:
        raise RuntimeError(f"{context} missing required fields: {', '.join(missing)}")
    return target


def _guess_repo_target_name_for_component(
    comp_name: str,
    context_hint: str,
    repo_target_map: Dict[str, Dict[str, Any]],
) -> str:
    names = list(repo_target_map.keys())
    if not names:
        return ""
    normalized_comp = comp_name.lower()
    context_hint = context_hint.lower()
    api_tokens = ("api", "backend", "migrate", "db-migrate")
    web_tokens = ("web", "ui", "frontend", "site")
    wants_web = any(token in normalized_comp for token in web_tokens) or any(
        token in context_hint for token in ("/web", "frontend", "/ui")
    )
    wants_api = any(token in normalized_comp for token in api_tokens) or any(
        token in context_hint for token in ("/api", "/migrate", "backend")
    )

    def _contains_any(value: str, tokens: tuple[str, ...]) -> bool:
        value = value.lower()
        return any(token in value for token in tokens)

    for name, target in repo_target_map.items():
        haystack = " ".join(
            [
                str(name or ""),
                str(target.get("path_root") or ""),
                str(target.get("url") or ""),
            ]
        )
        if wants_web and _contains_any(haystack, web_tokens):
            return name
        if wants_api and _contains_any(haystack, api_tokens):
            return name

    if wants_web and "xyn-ui" in repo_target_map:
        return "xyn-ui"
    if wants_api and "xyn-api" in repo_target_map:
        return "xyn-api"
    return ""


def _build_module_catalog() -> Dict[str, Any]:
    repo_targets = _default_repo_targets()
    catalog: List[Dict[str, Any]] = []
    seen: set[str] = set()
    registry_root = Path(__file__).resolve().parents[1] / "registry" / "modules"
    if registry_root.exists():
        for path in sorted(registry_root.glob("*.json")):
            try:
                spec = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            metadata = spec.get("metadata", {})
            module_spec = spec.get("module", {})
            module_id = metadata.get("name") or path.stem
            entry = {
                "id": module_id,
                "version": metadata.get("version", "0.1.0"),
                "capabilities": module_spec.get("capabilitiesProvided", []),
                "repo": {
                    "name": "xyn-api",
                    "url": repo_targets[0]["url"],
                    "ref": repo_targets[0]["ref"],
                    "path_root": f"backend/registry/modules/{path.name}",
                },
                "templates": ["module-spec", "docs"],
                "default_work_items": [],
            }
            catalog.append(entry)
            seen.add(module_id)

    curated = [
        {
            "id": "ems-api",
            "version": "0.1.0",
            "capabilities": [
                "app.api.fastapi",
                "ems.devices.api",
                "ems.reports.api",
                "authn.jwt.validate",
                "authz.rbac.enforce",
                "storage.postgres",
                "storage.migrations.alembic",
            ],
            "repo": {
                "name": repo_targets[0]["name"],
                "url": repo_targets[0]["url"],
                "ref": repo_targets[0]["ref"],
                "path_root": "apps/ems-api",
            },
            "templates": [
                "fastapi-scaffold",
                "jwt-protect",
                "devices-rbac",
                "devices-persistence",
            ],
            "default_work_items": ["ems-api-scaffold"],
        },
        {
            "id": "ems-ui",
            "version": "0.1.0",
            "capabilities": ["app.ui.react", "ems.devices.ui", "ems.reports.ui"],
            "repo": {
                "name": repo_targets[1]["name"],
                "url": repo_targets[1]["url"],
                "ref": repo_targets[1]["ref"],
                "path_root": "apps/ems-ui",
            },
            "templates": ["react-scaffold", "ems-ui-devices"],
            "default_work_items": ["ems-ui-scaffold"],
        },
        {
            "id": "ems-stack",
            "version": "0.1.0",
            "capabilities": ["deploy.compose.local", "proxy.nginx"],
            "repo": {
                "name": repo_targets[0]["name"],
                "url": repo_targets[0]["url"],
                "ref": repo_targets[0]["ref"],
                "path_root": "apps/ems-stack",
            },
            "templates": ["compose-chassis", "verify-stack"],
            "default_work_items": ["ems-stack-prod-web"],
        },
        {
            "id": "storage-postgres",
            "version": "0.1.0",
            "capabilities": ["storage.postgres"],
            "repo": {
                "name": repo_targets[0]["name"],
                "url": repo_targets[0]["url"],
                "ref": repo_targets[0]["ref"],
                "path_root": "apps/ems-api",
            },
            "templates": ["db-foundation"],
            "default_work_items": ["ems-api-db-foundation"],
        },
        {
            "id": "migrations-alembic",
            "version": "0.1.0",
            "capabilities": ["storage.migrations.alembic"],
            "repo": {
                "name": repo_targets[0]["name"],
                "url": repo_targets[0]["url"],
                "ref": repo_targets[0]["ref"],
                "path_root": "apps/ems-api",
            },
            "templates": ["alembic-migrations"],
            "default_work_items": ["ems-api-alembic-migrations"],
        },
    ]
    for entry in curated:
        if entry["id"] in seen:
            continue
        catalog.append(entry)
        seen.add(entry["id"])

    return {
        "schema_version": "module_catalog.v1",
        "generated_at": timezone.now().isoformat(),
        "modules": catalog,
    }


def _acceptance_checks_for_blueprint(
    blueprint: Blueprint, release_target: Optional[Dict[str, Any]] = None
) -> Dict[str, List[str]]:
    metadata = blueprint.metadata_json or {}
    acceptance = metadata.get("acceptance_checks")
    if isinstance(acceptance, dict):
        return {key: list(value) for key, value in acceptance.items()}
    deploy_meta = metadata.get("deploy") or {}
    tls_meta = metadata.get("tls") or {}
    image_deploy_enabled = False
    if release_target:
        deploy_target = release_target.get("target_instance_id")
        deploy_fqdn = release_target.get("fqdn")
        tls_meta = release_target.get("tls") or {}
        runtime_meta = release_target.get("runtime") or {}
        mode = _normalize_runtime_mode(runtime_meta)
        image_deploy_enabled = mode == "compose_images"
    else:
        deploy_target = deploy_meta.get("target_instance_id") or deploy_meta.get("target_instance") or deploy_meta.get(
            "target_instance_name"
        )
        deploy_fqdn = deploy_meta.get("primary_fqdn") or deploy_meta.get("fqdn")
    if not deploy_fqdn:
        environments = metadata.get("environments") or []
        if isinstance(environments, list) and environments:
            env = environments[0] if isinstance(environments[0], dict) else {}
            deploy_fqdn = env.get("fqdn")
    remote_enabled = bool(deploy_target and deploy_fqdn)
    tls_mode = str(tls_meta.get("mode") or "").lower()
    tls_enabled = tls_mode in {"nginx+acme", "acme", "letsencrypt", "host-ingress", "embedded"}
    blueprint_fqn = f"{blueprint.namespace}.{blueprint.name}"
    if blueprint_fqn == "core.ems.platform":
        checks = {
            "local_chassis": ["ems-stack-prod-web"],
            "jwt_required": ["ems-api-jwt-protect-me", "ems-stack-pass-jwt-secret-and-verify-me"],
            "rbac_devices": ["ems-api-devices-rbac", "ems-stack-verify-rbac"],
            "persistence_devices": ["ems-api-devices-postgres", "ems-stack-verify-persistence"],
        }
        if remote_enabled:
            if image_deploy_enabled:
                checks["remote_http_health"] = [
                    "build.publish_images.container",
                    "dns.ensure_record.route53",
                    "deploy.apply_remote_compose.pull",
                    "verify.public_http",
                ]
            else:
                checks["remote_http_health"] = [
                    "dns.ensure_record.route53",
                    "deploy.apply_remote_compose.ssm",
                    "verify.public_http",
                ]
        if remote_enabled and tls_enabled:
            if image_deploy_enabled:
                checks["remote_https_health"] = (
                    [
                        "build.publish_images.container",
                        "dns.ensure_record.route53",
                        "deploy.apply_remote_compose.pull",
                        "verify.public_http",
                        "verify.public_https",
                    ]
                    if tls_mode == "host-ingress"
                    else [
                        "build.publish_images.container",
                        "dns.ensure_record.route53",
                        "deploy.apply_remote_compose.pull",
                        "verify.public_http",
                        "tls.acme_http01",
                        "ingress.nginx_tls_configure",
                        "verify.public_https",
                    ]
                )
            else:
                checks["remote_https_health"] = (
                    ["verify.public_https"]
                    if tls_mode == "host-ingress"
                    else [
                        "tls.acme_http01",
                        "ingress.nginx_tls_configure",
                        "verify.public_https",
                    ]
                )
        return checks
    return {}


def _build_run_history_summary(
    blueprint: Blueprint, release_target: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    completed: List[Dict[str, Any]] = []
    completed_ids: set[str] = set()
    remote_verify_ok = False
    remote_https_ok = False
    tasks = DevTask.objects.filter(
        source_entity_type="blueprint", source_entity_id=blueprint.id
    ).select_related("result_run")
    for task in tasks:
        if not task.result_run:
            continue
        artifacts = list(task.result_run.artifacts.all())
        result = None
        deploy_result = None
        verify_result = None
        for artifact in artifacts:
            if artifact.name == "codegen_result.json":
                result = _read_run_artifact_json(artifact)
                break
        for artifact in artifacts:
            if artifact.name == "deploy_result.json":
                deploy_result = _read_run_artifact_json(artifact)
            if artifact.name == "deploy_verify.json":
                verify_result = _read_run_artifact_json(artifact)
        success = False
        commit_sha = ""
        if result:
            success = bool(result.get("success"))
            repo_results = result.get("repo_results") or []
            for repo in repo_results:
                commit = repo.get("commit") or {}
                if commit.get("sha"):
                    commit_sha = commit.get("sha")
                    break
        elif deploy_result:
            outcome = deploy_result.get("outcome")
            success = outcome in {"succeeded", "noop"}
        else:
            success = task.status == "succeeded"
        outcome = "succeeded" if task.status == "succeeded" and success else "failed"
        completed.append(
            {
                "work_item_id": task.work_item_id or "",
                "outcome": outcome,
                "commit_sha": commit_sha,
                "artifacts": [artifact.name for artifact in artifacts],
            }
        )
        if task.work_item_id and outcome == "succeeded":
            completed_ids.add(task.work_item_id)
        if verify_result and isinstance(verify_result, dict):
            checks = verify_result.get("checks") or []
            health_ok = False
            api_ok = False
            https_health_ok = False
            https_api_ok = False
            for check in checks:
                if check.get("name") in {"public_health", "http://ems.xyence.io/health", "health"} and check.get("ok"):
                    health_ok = True
                if check.get("name") in {
                    "public_api_health",
                    "http://ems.xyence.io/api/health",
                    "api_health",
                } and check.get("ok"):
                    api_ok = True
                if check.get("name") in {"public_https_health"} and check.get("ok"):
                    https_health_ok = True
                if check.get("name") in {"public_https_api_health"} and check.get("ok"):
                    https_api_ok = True
            if health_ok and api_ok:
                remote_verify_ok = True
            if https_health_ok and https_api_ok:
                remote_https_ok = True

    acceptance_map = _acceptance_checks_for_blueprint(blueprint, release_target)
    acceptance_status = []
    for check_id, work_items in acceptance_map.items():
        if check_id == "remote_http_health":
            status = "pass" if remote_verify_ok else "fail"
        elif check_id == "remote_https_health":
            status = "pass" if remote_https_ok else "fail"
        else:
            status = "pass" if all(item in completed_ids for item in work_items) else "fail"
        acceptance_status.append({"id": check_id, "status": status})

    return {
        "schema_version": "run_history_summary.v1",
        "blueprint_id": str(blueprint.id),
        "generated_at": timezone.now().isoformat(),
        "completed_work_items": completed,
        "acceptance_checks_status": acceptance_status,
    }


def _normalize_runtime_mode(runtime_meta: Dict[str, Any]) -> str:
    mode = runtime_meta.get("mode")
    if mode in {"compose_build", "compose_images"}:
        return mode
    if runtime_meta.get("image_deploy"):
        return "compose_images"
    return "compose_build"


def _next_release_version_for_blueprint(blueprint_id: str) -> str:
    qs = Release.objects.filter(blueprint_id=blueprint_id).values_list("version", flat=True)
    max_seen = 0
    for version in qs:
        match = re.match(r"^v(\d+)$", str(version or "").strip(), flags=re.IGNORECASE)
        if not match:
            continue
        number = int(match.group(1))
        if number > max_seen:
            max_seen = number
    return f"v{max_seen + 1}"


def _select_next_slice(
    blueprint: Blueprint,
    work_items: List[Dict[str, Any]],
    run_history_summary: Dict[str, Any],
    release_target: Optional[Dict[str, Any]] = None,
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    priority = [
        "remote_https_health",
        "remote_http_health",
        "local_chassis",
        "jwt_required",
        "rbac_devices",
        "persistence_devices",
        "oidc",
        "route53_acme_ssm",
    ]
    status_map = {entry["id"]: entry["status"] for entry in run_history_summary.get("acceptance_checks_status", [])}
    next_gap = None
    for gap in priority:
        if gap not in status_map:
            continue
        if status_map.get(gap) != "pass":
            next_gap = gap
            break
    completed_ids = {
        entry.get("work_item_id")
        for entry in run_history_summary.get("completed_work_items", [])
        if entry.get("outcome") == "succeeded"
    }
    image_deploy_present = any(item.get("id") == "deploy.apply_remote_compose.pull" for item in work_items)
    build_present = any(
        item.get("id") in {"build.publish_images.container", "build.publish_images.components"}
        for item in work_items
    )
    metadata = blueprint.metadata_json or {}
    tls_meta = metadata.get("tls") or {}
    if release_target:
        tls_meta = release_target.get("tls") or tls_meta
    tls_mode = str(tls_meta.get("mode") or "").lower()
    host_ingress = tls_mode == "host-ingress"
    build_item_id = (
        "build.publish_images.components"
        if any(item.get("id") == "build.publish_images.components" for item in work_items)
        else "build.publish_images.container"
    )
    remote_http_items = (
        [
            build_item_id,
            "release.validate_manifest.pinned",
            "dns.ensure_record.route53",
            "deploy.apply_remote_compose.pull",
            "verify.public_http",
        ]
        if image_deploy_present and build_present
        else (
            [
                "release.validate_manifest.pinned",
                "dns.ensure_record.route53",
                "deploy.apply_remote_compose.pull",
                "verify.public_http",
            ]
            if image_deploy_present
            else ["dns.ensure_record.route53", "deploy.apply_remote_compose.ssm", "verify.public_http"]
        )
    )
    remote_https_items = (
        remote_http_items + ["verify.public_https"]
        if host_ingress
        else (
            [
                build_item_id,
                "release.validate_manifest.pinned",
                "dns.ensure_record.route53",
                "deploy.apply_remote_compose.pull",
                "verify.public_http",
                "tls.acme_http01",
                "ingress.nginx_tls_configure",
                "verify.public_https",
            ]
            if image_deploy_present and build_present
            else (
                [
                    "release.validate_manifest.pinned",
                    "dns.ensure_record.route53",
                    "deploy.apply_remote_compose.pull",
                    "verify.public_http",
                    "tls.acme_http01",
                    "ingress.nginx_tls_configure",
                    "verify.public_https",
                ]
                if image_deploy_present
                else [
                    "dns.ensure_record.route53",
                    "deploy.apply_remote_compose.ssm",
                    "verify.public_http",
                    "tls.acme_http01",
                    "ingress.nginx_tls_configure",
                    "verify.public_https",
                ]
            )
        )
    )
    gap_to_items = {
        "local_chassis": ["ems-stack-prod-web"],
        "jwt_required": ["ems-authn-jwt-module", "ems-api-jwt-protect-me", "ems-ui-token-input-me-call", "ems-stack-pass-jwt-secret-and-verify-me"],
        "rbac_devices": ["ems-authz-rbac-module", "ems-api-devices-rbac", "ems-ui-devices-role-aware", "ems-stack-verify-rbac"],
        "persistence_devices": [
            "ems-api-db-foundation",
            "ems-api-alembic-migrations",
            "ems-api-container-startup-migrate",
            "ems-api-devices-postgres",
            "ems-stack-verify-persistence",
        ],
        "oidc": ["ems-api-authn-oidc", "ems-ui-auth"],
        "route53_acme_ssm": ["ems-api-route53", "ems-api-acme", "ems-ssm-deploy"],
        "remote_http_health": remote_http_items,
        "remote_https_health": remote_https_items,
    }
    if not next_gap:
        return work_items, {"gaps_detected": [], "modules_selected": [], "why_next": ["All known gaps satisfied."]}
    selected_ids = gap_to_items.get(next_gap, [])
    selected = [item for item in work_items if item["id"] in selected_ids and item["id"] not in completed_ids]
    module_scaffolds = [
        item
        for item in work_items
        if item.get("type") == "scaffold"
        and isinstance(item.get("id"), str)
        and item["id"].endswith("-module")
        and item["id"] not in completed_ids
    ]
    for item in module_scaffolds:
        if item not in selected:
            selected.append(item)
    rationale = {
        "gaps_detected": [next_gap],
        "modules_selected": [],
        "why_next": [f"Selected next slice for gap {next_gap}."],
    }
    return selected or work_items, rationale


def _annotate_work_items(
    work_items: List[Dict[str, Any]],
    module_catalog: Dict[str, Any],
    preferred_ingress_module: str = "ingress-nginx-acme",
) -> None:
    module_versions = {m["id"]: m.get("version", "0.1.0") for m in module_catalog.get("modules", [])}
    work_item_caps = {
        "ems-api-scaffold": ["app.api.fastapi"],
        "ems-ui-scaffold": ["app.ui.react"],
        "ems-compose-local-chassis": ["deploy.compose.local"],
        "ems-stack-prod-web": ["deploy.compose.local", "runtime.web.static", "runtime.reverse_proxy.http"],
        "ems-authn-jwt-module": ["authn.jwt.validate"],
        "ems-authz-rbac-module": ["authz.rbac.enforce"],
        "ems-api-jwt-protect-me": ["authn.jwt.validate"],
        "ems-api-devices-rbac": ["authz.rbac.enforce", "ems.devices.api"],
        "ems-api-devices-postgres": ["storage.postgres", "ems.devices.persistence"],
        "ems-api-db-foundation": ["storage.postgres"],
        "ems-api-alembic-migrations": ["storage.migrations.alembic"],
        "ems-api-container-startup-migrate": ["storage.migrations.alembic"],
        "ems-stack-verify-persistence": ["deploy.compose.local.verify"],
        "ems-stack-verify-rbac": ["deploy.compose.local.verify"],
        "ems-stack-pass-jwt-secret-and-verify-me": ["deploy.compose.local.verify"],
        "ems-ui-token-input-me-call": ["app.ui.react", "authn.jwt.validate"],
        "ems-ui-devices-role-aware": ["app.ui.react", "authz.rbac.enforce"],
        "dns-route53-module": ["dns.route53.records"],
        "deploy-ssm-compose-module": ["runtime.compose.apply_remote"],
        "ingress-nginx-acme-module": ["ingress.tls.acme_http01"],
        "ingress-traefik-acme-module": ["ingress.tls.acme_http01"],
        "build-container-publish-module": ["build.container.image", "publish.container.registry"],
        "runtime-compose-pull-apply-module": ["runtime.compose.pull_apply_remote"],
        "dns-route53-ensure-record": ["dns.route53.records"],
        "dns.ensure_record.route53": ["dns.route53.records"],
        "remote-deploy-compose-ssm": ["runtime.compose.apply_remote", "deploy.ssm.run_shell"],
        "deploy.apply_remote_compose.ssm": ["runtime.compose.apply_remote", "deploy.ssm.run_shell"],
        "build.publish_images.container": ["build.container.image", "publish.container.registry"],
        "build.publish_images.components": ["build.container.image", "publish.container.registry"],
        "release.validate_manifest.pinned": ["release.manifest.pinned"],
        "deploy.apply_remote_compose.pull": ["runtime.compose.pull_apply_remote"],
        "remote-deploy-verify-public": ["deploy.verify.public_http"],
        "verify.public_http": ["deploy.verify.public_http"],
        "tls-acme-bootstrap": ["ingress.tls.acme_http01"],
        "tls.acme_http01": ["ingress.tls.acme_http01"],
        "tls-nginx-configure": ["ingress.nginx.tls_configure", "ingress.nginx.reverse_proxy"],
        "ingress.nginx_tls_configure": ["ingress.nginx.tls_configure", "ingress.nginx.reverse_proxy"],
        "remote-deploy-verify-https": ["deploy.verify.public_https", "ingress.tls.acme_http01"],
        "verify.public_https": ["deploy.verify.public_https", "ingress.tls.acme_http01"],
    }
    work_item_modules = {
        "ems-api-scaffold": ["ems-api"],
        "ems-ui-scaffold": ["ems-ui"],
        "ems-compose-local-chassis": ["ems-stack"],
        "ems-stack-prod-web": ["ems-stack", "runtime-web-static-nginx"],
        "ems-authn-jwt-module": ["authn-jwt"],
        "ems-authz-rbac-module": ["authz-rbac"],
        "ems-api-jwt-protect-me": ["authn-jwt", "ems-api"],
        "ems-api-devices-rbac": ["authz-rbac", "ems-api"],
        "ems-api-devices-postgres": ["storage-postgres", "ems-api"],
        "ems-api-db-foundation": ["storage-postgres"],
        "ems-api-alembic-migrations": ["migrations-alembic"],
        "ems-api-container-startup-migrate": ["migrations-alembic"],
        "ems-stack-verify-persistence": ["ems-stack"],
        "ems-stack-verify-rbac": ["ems-stack"],
        "ems-stack-pass-jwt-secret-and-verify-me": ["ems-stack"],
        "ems-ui-token-input-me-call": ["ems-ui"],
        "ems-ui-devices-role-aware": ["ems-ui"],
        "dns-route53-module": ["dns-route53"],
        "deploy-ssm-compose-module": ["deploy-ssm-compose"],
        "ingress-nginx-acme-module": ["ingress-nginx-acme"],
        "ingress-traefik-acme-module": ["ingress-traefik-acme"],
        "build-container-publish-module": ["build-container-publish"],
        "runtime-compose-pull-apply-module": ["runtime-compose-pull-apply"],
        "dns-route53-ensure-record": ["dns-route53"],
        "dns.ensure_record.route53": ["dns-route53"],
        "remote-deploy-compose-ssm": ["deploy-ssm-compose"],
        "deploy.apply_remote_compose.ssm": ["deploy-ssm-compose"],
        "build.publish_images.container": ["build-container-publish"],
        "build.publish_images.components": ["build-container-publish"],
        "release.validate_manifest.pinned": ["build-container-publish"],
        "deploy.apply_remote_compose.pull": ["runtime-compose-pull-apply"],
        "remote-deploy-verify-public": ["deploy-ssm-compose"],
        "verify.public_http": ["deploy-ssm-compose"],
        "tls-acme-bootstrap": [preferred_ingress_module],
        "tls.acme_http01": [preferred_ingress_module],
        "tls-nginx-configure": [preferred_ingress_module],
        "ingress.nginx_tls_configure": [preferred_ingress_module],
        "remote-deploy-verify-https": [preferred_ingress_module],
        "verify.public_https": [preferred_ingress_module],
    }
    for item in work_items:
        item_id = item.get("id")
        caps = work_item_caps.get(item_id, [])
        modules = work_item_modules.get(item_id, [])
        if caps:
            item["capabilities_required"] = caps
        if modules:
            item["module_refs"] = [{"id": module_id, "version": module_versions.get(module_id, "0.1.0")} for module_id in modules]
            item.setdefault("labels", [])
            for module_id in modules:
                if f"module:{module_id}" not in item["labels"]:
                    item["labels"].append(f"module:{module_id}")
            for cap in caps:
                if f"capability:{cap}" not in item["labels"]:
                    item["labels"].append(f"capability:{cap}")


def _generate_implementation_plan(
    blueprint: Blueprint,
    module_catalog: Optional[Dict[str, Any]] = None,
    run_history_summary: Optional[Dict[str, Any]] = None,
    release_target: Optional[Dict[str, Any]] = None,
    manifest_override: bool = False,
) -> Dict[str, Any]:
    blueprint_fqn = f"{blueprint.namespace}.{blueprint.name}"
    planned_release_version = _next_release_version_for_blueprint(str(blueprint.id))
    repo_targets = _default_repo_targets()
    if blueprint_fqn != "core.ems.platform":
        # Non-EMS blueprints should default to repo-root paths so generated
        # component build contexts (e.g. apps/<app>/api) resolve correctly.
        repo_targets = [{**target, "path_root": "."} for target in repo_targets]
    blueprint_intent = _extract_blueprint_intent(blueprint)
    intent_requirements = blueprint_intent.get("requirements") if isinstance(blueprint_intent.get("requirements"), dict) else {}
    intent_prompt = (
        blueprint_intent.get("prompt", {}).get("text")
        if isinstance(blueprint_intent.get("prompt"), dict)
        else ""
    )
    work_items: List[Dict[str, Any]] = []
    if blueprint_fqn == "core.ems.platform":
        work_items = [
            {
                "id": "ems-api-scaffold",
                "title": "Scaffold EMS API service",
                "description": "Create FastAPI scaffolding, router wiring, and health checks.",
                "type": "scaffold",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"], "context": ["ems-platform-blueprint"]},
                "outputs": {
                    "paths": [
                        "apps/ems-api/README.md",
                        "apps/ems-api/requirements.txt",
                        "apps/ems-api/Dockerfile",
                        "apps/ems-api/pyproject.toml",
                        "apps/ems-api/ems_api/__init__.py",
                        "apps/ems-api/ems_api/main.py",
                        "apps/ems-api/ems_api/routes/__init__.py",
                        "apps/ems-api/ems_api/routes/health.py",
                        "apps/ems-api/ems_api/routes/devices.py",
                        "apps/ems-api/ems_api/routes/reports.py",
                        "apps/ems-api/ems_api/tests/test_health.py",
                    ]
                },
                "acceptance_criteria": [
                    "FastAPI app boots with /health endpoint.",
                    "Project README describes local run steps.",
                ],
                "verify": [
                    {
                        "name": "compile",
                        "command": "python -m compileall ems_api",
                        "cwd": "apps/ems-api",
                    },
                    {
                        "name": "import app",
                        "command": "python -c \"import ems_api.main\"",
                        "cwd": "apps/ems-api",
                    },
                ],
                "depends_on": [],
                "labels": ["scaffold", "api"],
            },
            {
                "id": "ems-api-authn-oidc",
                "title": "Add OIDC authn scaffolding",
                "description": "Add OIDC config placeholders and login flow stubs.",
                "type": "feature",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"], "context": ["xyn-planner-canon"]},
                "outputs": {
                    "paths": [
                        "apps/ems-api/ems_api/auth/__init__.py",
                        "apps/ems-api/ems_api/auth/oidc.py",
                        "apps/ems-api/ems_api/deps.py",
                        "apps/ems-api/ems_api/tests/test_auth.py",
                    ]
                },
                "acceptance_criteria": [
                    "OIDC settings present with placeholders.",
                    "Login endpoint returns placeholder JWT.",
                ],
                "verify": [
                    {"name": "auth-file", "command": "test -f ems_api/auth/oidc.py", "cwd": "apps/ems-api"},
                ],
                "depends_on": ["ems-api-scaffold"],
                "labels": ["auth", "api"],
            },
            {
                "id": "ems-api-rbac",
                "title": "Add RBAC primitives",
                "description": "Define roles, policies, and middleware checks.",
                "type": "feature",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-api/ems_api/auth/rbac.py",
                        "apps/ems-api/ems_api/tests/test_rbac.py",
                    ]
                },
                "acceptance_criteria": [
                    "Roles Admin/Operator/Viewer defined.",
                    "RBAC check utility available.",
                ],
                "verify": [
                    {"name": "rbac-file", "command": "test -f ems_api/auth/rbac.py", "cwd": "apps/ems-api"},
                ],
                "depends_on": ["ems-api-authn-oidc"],
                "labels": ["rbac", "api"],
            },
            {
                "id": "ems-api-devices",
                "title": "Device CRUD endpoints",
                "description": "Stub device CRUD endpoints with RBAC guards.",
                "type": "feature",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-api/ems_api/routes/devices.py",
                        "apps/ems-api/ems_api/tests/test_devices.py",
                    ]
                },
                "acceptance_criteria": [
                    "CRUD endpoints exist for devices.",
                    "Viewer role can only read.",
                ],
                "verify": [
                    {"name": "devices-file", "command": "test -f ems_api/routes/devices.py", "cwd": "apps/ems-api"},
                ],
                "depends_on": ["ems-api-rbac"],
                "labels": ["api", "devices"],
            },
            {
                "id": "ems-api-reports",
                "title": "Reports endpoint",
                "description": "Stub reports endpoint with viewer access.",
                "type": "feature",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-api/ems_api/routes/reports.py",
                        "apps/ems-api/ems_api/tests/test_reports.py",
                    ]
                },
                "acceptance_criteria": [
                    "Reports endpoint returns placeholder report data.",
                ],
                "verify": [
                    {"name": "reports-file", "command": "test -f ems_api/routes/reports.py", "cwd": "apps/ems-api"},
                ],
                "depends_on": ["ems-api-rbac"],
                "labels": ["api", "reports"],
            },
            {
                "id": "ems-ui-scaffold",
                "title": "Scaffold EMS UI",
                "description": "Create React app shell with routing and entrypoints.",
                "type": "scaffold",
                "repo_targets": [repo_targets[1]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-ui/README.md",
                        "apps/ems-ui/Dockerfile",
                        "apps/ems-ui/nginx.conf",
                        "apps/ems-ui/package.json",
                        "apps/ems-ui/tsconfig.json",
                        "apps/ems-ui/vite.config.ts",
                        "apps/ems-ui/index.html",
                        "apps/ems-ui/src/main.tsx",
                        "apps/ems-ui/src/App.tsx",
                        "apps/ems-ui/src/routes.tsx",
                        "apps/ems-ui/src/styles.css",
                    ]
                },
                "acceptance_criteria": [
                    "UI app renders basic layout and navigation.",
                ],
                "verify": [
                    {
                        "name": "ui-structure",
                        "command": "test -f Dockerfile && test -f nginx.conf && test -f src/App.tsx && test -f src/main.tsx && test -f src/routes.tsx && test -f src/auth/Login.tsx && test -f src/devices/DeviceList.tsx && test -f src/reports/Reports.tsx && grep -q \"/api/health\" src/auth/Login.tsx && grep -q \"/api/me\" src/auth/Login.tsx",
                        "cwd": "apps/ems-ui",
                    },
                ],
                "depends_on": [],
                "labels": ["scaffold", "ui"],
            },
            {
                "id": "ems-authn-jwt-module",
                "title": "JWT auth module scaffold",
                "description": "Define reusable JWT auth module spec and docs.",
                "type": "scaffold",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": "backend/registry/modules",
                        "auth": "https_token",
                        "allow_write": True,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "backend/registry/modules/authn-jwt.json",
                        "backend/registry/modules/README.md",
                    ]
                },
                "acceptance_criteria": [
                    "Module spec describes JWT validation capability and configuration.",
                ],
                "verify": [
                    {
                        "name": "module-spec",
                        "command": "test -f backend/registry/modules/authn-jwt.json",
                        "cwd": ".",
                    }
                ],
                "depends_on": [],
                "labels": ["module", "auth"],
            },
            {
                "id": "ems-authz-rbac-module",
                "title": "RBAC module scaffold",
                "description": "Define reusable RBAC module spec and docs.",
                "type": "scaffold",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": "backend/registry/modules",
                        "auth": "https_token",
                        "allow_write": True,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {"paths": ["backend/registry/modules/authz-rbac.json"]},
                "acceptance_criteria": [
                    "Module spec describes RBAC enforcement capability and roles.",
                ],
                "verify": [
                    {
                        "name": "rbac-module-spec",
                        "command": "test -f backend/registry/modules/authz-rbac.json",
                        "cwd": ".",
                    }
                ],
                "depends_on": [],
                "labels": ["module", "authz"],
            },
            {
                "id": "ems-api-jwt-protect-me",
                "title": "Protect /me with JWT",
                "description": "Add JWT validation, /me endpoint, and dev token helper.",
                "type": "feature",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-api/ems_api/auth.py",
                        "apps/ems-api/ems_api/routes/me.py",
                        "apps/ems-api/scripts/issue_dev_token.py",
                        "apps/ems-api/requirements.txt",
                    ]
                },
                "acceptance_criteria": [
                    "/me returns claims with valid JWT.",
                    "/me returns 401 when unauthenticated.",
                ],
                "verify": [
                    {
                        "name": "jwt-files",
                        "command": "test -f ems_api/auth.py && test -f ems_api/routes/me.py && test -f scripts/issue_dev_token.py",
                        "cwd": "apps/ems-api",
                    },
                ],
                "depends_on": ["ems-authn-jwt-module", "ems-api-scaffold"],
                "labels": ["api", "auth"],
            },
            {
                "id": "ems-api-db-foundation",
                "title": "Database foundation",
                "description": "SQLAlchemy base, session utilities, and device model.",
                "type": "feature",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-api/ems_api/db.py",
                        "apps/ems-api/ems_api/models.py",
                    ]
                },
                "acceptance_criteria": ["Database utilities and models exist."],
                "verify": [
                    {"name": "db-files", "command": "test -f ems_api/db.py && test -f ems_api/models.py", "cwd": "apps/ems-api"},
                ],
                "depends_on": ["ems-api-jwt-protect-me"],
                "labels": ["api", "db"],
            },
            {
                "id": "ems-api-alembic-migrations",
                "title": "Alembic migrations",
                "description": "Add Alembic config and initial devices migration.",
                "type": "feature",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-api/alembic.ini",
                        "apps/ems-api/alembic/env.py",
                        "apps/ems-api/alembic/versions/20260206_ems_devices.py",
                    ]
                },
                "acceptance_criteria": ["Alembic migration for devices exists."],
                "verify": [
                    {"name": "alembic-files", "command": "test -f alembic.ini && test -f alembic/env.py", "cwd": "apps/ems-api"},
                ],
                "depends_on": ["ems-api-db-foundation"],
                "labels": ["api", "db"],
            },
            {
                "id": "ems-api-container-startup-migrate",
                "title": "Run migrations on startup",
                "description": "Add entrypoint to run alembic before uvicorn.",
                "type": "feature",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-api/scripts/entrypoint.sh",
                        "apps/ems-api/Dockerfile",
                    ]
                },
                "acceptance_criteria": ["Container runs alembic upgrade head on boot."],
                "verify": [
                    {"name": "entrypoint", "command": "test -f scripts/entrypoint.sh", "cwd": "apps/ems-api"},
                ],
                "depends_on": ["ems-api-alembic-migrations"],
                "labels": ["api", "db", "deploy"],
            },
            {
                "id": "ems-api-devices-rbac",
                "title": "RBAC enforcement for devices",
                "description": "Require admin for device writes and allow viewer/admin reads.",
                "type": "feature",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-api/ems_api/rbac.py",
                        "apps/ems-api/ems_api/routes/devices.py",
                    ]
                },
                "acceptance_criteria": [
                    "Viewer can list devices but cannot create/delete.",
                    "Admin can create/delete devices.",
                ],
                "verify": [
                    {
                        "name": "devices-rbac",
                        "command": "test -f ems_api/rbac.py && grep -q require_roles ems_api/routes/devices.py",
                        "cwd": "apps/ems-api",
                    }
                ],
                "depends_on": ["ems-api-jwt-protect-me", "ems-authz-rbac-module"],
                "labels": ["api", "authz"],
            },
            {
                "id": "ems-api-devices-postgres",
                "title": "Persist devices in Postgres",
                "description": "Refactor devices CRUD to use SQLAlchemy/Postgres.",
                "type": "feature",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {"paths": ["apps/ems-api/ems_api/routes/devices.py"]},
                "acceptance_criteria": ["Devices CRUD uses database storage."],
                "verify": [
                    {"name": "devices-db", "command": "grep -q 'Session' ems_api/routes/devices.py", "cwd": "apps/ems-api"},
                ],
                "depends_on": ["ems-api-db-foundation", "ems-api-devices-rbac"],
                "labels": ["api", "db"],
            },
            {
                "id": "ems-token-script-roles",
                "title": "Dev token roles",
                "description": "Allow dev token script to issue admin/viewer tokens.",
                "type": "feature",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {"paths": ["apps/ems-api/scripts/issue_dev_token.py"]},
                "acceptance_criteria": [
                    "issue_dev_token.py supports --role admin|viewer.",
                ],
                "verify": [
                    {
                        "name": "token-roles",
                        "command": "grep -q -- '--role' scripts/issue_dev_token.py",
                        "cwd": "apps/ems-api",
                    }
                ],
                "depends_on": ["ems-api-jwt-protect-me"],
                "labels": ["api", "auth"],
            },
            {
                "id": "ems-ui-token-input-me-call",
                "title": "UI token input and /me call",
                "description": "Add token input and /api/me call to UI login.",
                "type": "feature",
                "repo_targets": [repo_targets[1]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-ui/src/auth/Login.tsx",
                    ]
                },
                "acceptance_criteria": [
                    "UI shows API health and /api/me identity response.",
                ],
                "verify": [
                    {
                        "name": "login-me-call",
                        "command": "test -f src/auth/Login.tsx && grep -q \"/api/me\" src/auth/Login.tsx",
                        "cwd": "apps/ems-ui",
                    },
                ],
                "depends_on": ["ems-ui-scaffold", "ems-api-jwt-protect-me"],
                "labels": ["ui", "auth"],
            },
            {
                "id": "ems-ui-devices-role-aware",
                "title": "Role-aware devices UI",
                "description": "Render device list and show admin controls only for admin role.",
                "type": "feature",
                "repo_targets": [repo_targets[1]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {"paths": ["apps/ems-ui/src/devices/DeviceList.tsx"]},
                "acceptance_criteria": [
                    "Viewer sees list only; admin sees create/delete controls.",
                ],
                "verify": [
                    {
                        "name": "devices-ui",
                        "command": "grep -q /api/devices src/devices/DeviceList.tsx",
                        "cwd": "apps/ems-ui",
                    }
                ],
                "depends_on": ["ems-ui-scaffold", "ems-api-devices-rbac"],
                "labels": ["ui", "authz"],
            },
            {
                "id": "ems-stack-pass-jwt-secret-and-verify-me",
                "title": "Chassis JWT config and /me verification",
                "description": "Pass EMS_JWT_SECRET and verify /api/me through the stack.",
                "type": "deploy",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": "apps/ems-stack",
                        "auth": "https_token",
                        "allow_write": True,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-stack/.env.example",
                        "apps/ems-stack/docker-compose.yml",
                        "apps/ems-stack/scripts/verify.sh",
                    ]
                },
                "acceptance_criteria": [
                    "Stack passes EMS_JWT_SECRET and /api/me checks in verify script.",
                ],
                "verify": [
                    {
                        "name": "stack-jwt-files",
                        "command": "grep -q EMS_JWT_SECRET apps/ems-stack/docker-compose.yml && grep -q /api/me apps/ems-stack/scripts/verify.sh",
                        "cwd": ".",
                    }
                ],
                "depends_on": ["ems-stack-prod-web", "ems-api-jwt-protect-me"],
                "labels": ["deploy", "auth"],
            },
            {
                "id": "ems-stack-verify-rbac",
                "title": "Chassis RBAC verification",
                "description": "Verify viewer/admin behavior for /api/devices.",
                "type": "deploy",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": "apps/ems-stack",
                        "auth": "https_token",
                        "allow_write": True,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {"paths": ["apps/ems-stack/scripts/verify.sh"]},
                "acceptance_criteria": [
                    "verify.sh asserts viewer 403 and admin 200/201 on /api/devices.",
                ],
                "verify": [
                    {
                        "name": "rbac-verify-script",
                        "command": "grep -q /api/devices apps/ems-stack/scripts/verify.sh && grep -q viewer apps/ems-stack/scripts/verify.sh",
                        "cwd": ".",
                    }
                ],
                "depends_on": ["ems-stack-pass-jwt-secret-and-verify-me", "ems-api-devices-rbac"],
                "labels": ["deploy", "authz"],
            },
            {
                "id": "ems-stack-verify-persistence",
                "title": "Verify device persistence",
                "description": "Ensure devices persist across ems-api restart.",
                "type": "deploy",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": "apps/ems-stack",
                        "auth": "https_token",
                        "allow_write": True,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {"paths": ["apps/ems-stack/scripts/verify.sh"]},
                "acceptance_criteria": ["verify.sh checks persistence across restart."],
                "verify": [
                    {"name": "persistence-check", "command": "grep -q persist1 apps/ems-stack/scripts/verify.sh", "cwd": "."},
                ],
                "depends_on": ["ems-stack-verify-rbac", "ems-api-devices-postgres"],
                "labels": ["deploy", "db"],
            },
            {
                "id": "ems-ui-auth",
                "title": "UI OIDC login view",
                "description": "Add login page and token handling stubs.",
                "type": "feature",
                "repo_targets": [repo_targets[1]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-ui/src/auth/Login.tsx",
                        "apps/ems-ui/src/auth/AuthProvider.tsx",
                    ]
                },
                "acceptance_criteria": [
                    "Login page exists with placeholder flow.",
                ],
                "verify": [
                    {"name": "login-view", "command": "test -f src/auth/Login.tsx", "cwd": "apps/ems-ui"},
                ],
                "depends_on": ["ems-ui-scaffold"],
                "labels": ["ui", "auth"],
            },
            {
                "id": "ems-ui-devices",
                "title": "UI device CRUD skeleton",
                "description": "Add device list and detail pages.",
                "type": "feature",
                "repo_targets": [repo_targets[1]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-ui/src/devices/DeviceList.tsx",
                        "apps/ems-ui/src/devices/DeviceDetail.tsx",
                    ]
                },
                "acceptance_criteria": [
                    "Device list page renders mock data.",
                ],
                "verify": [
                    {"name": "device-ui", "command": "test -f src/devices/DeviceList.tsx", "cwd": "apps/ems-ui"},
                ],
                "depends_on": ["ems-ui-scaffold"],
                "labels": ["ui", "devices"],
            },
            {
                "id": "ems-ui-reports",
                "title": "UI reports skeleton",
                "description": "Add reports page with placeholder charts.",
                "type": "feature",
                "repo_targets": [repo_targets[1]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {"paths": ["apps/ems-ui/src/reports/Reports.tsx"]},
                "acceptance_criteria": [
                    "Reports page exists and renders placeholder content.",
                ],
                "verify": [
                    {"name": "reports-ui", "command": "test -f src/reports/Reports.tsx", "cwd": "apps/ems-ui"},
                ],
                "depends_on": ["ems-ui-scaffold"],
                "labels": ["ui", "reports"],
            },
            {
                "id": "ems-deploy-compose",
                "title": "Docker compose + nginx/acme scaffold",
                "description": "Add docker-compose and nginx/acme placeholders for EMS.",
                "type": "deploy",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-api/deploy/README.md",
                        "apps/ems-api/deploy/docker-compose.yml",
                        "apps/ems-api/deploy/nginx.conf",
                    ]
                },
                "acceptance_criteria": [
                    "Compose file defines api + ui services.",
                ],
                "verify": [
                    {"name": "compose-file", "command": "test -f deploy/docker-compose.yml", "cwd": "apps/ems-api"},
                ],
                "depends_on": ["ems-api-scaffold", "ems-ui-scaffold"],
                "labels": ["deploy", "infra"],
            },
            {
                "id": "ems-stack-prod-web",
                "title": "Local docker-compose chassis (prod web)",
                "description": "Local EMS stack with ems-api, ems-web (static nginx), postgres.",
                "type": "deploy",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": "apps/ems-stack",
                        "auth": "https_token",
                        "allow_write": True,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-stack/README.md",
                        "apps/ems-stack/docker-compose.yml",
                        "apps/ems-stack/nginx/nginx.conf",
                        "apps/ems-stack/.env.example",
                        "apps/ems-stack/scripts/verify.sh",
                    ]
                },
                "acceptance_criteria": [
                    "Local stack can be brought up via docker-compose.",
                    "/health returns 200 via nginx.",
                    "UI root serves static HTML.",
                ],
                "verify": [
                    {
                        "name": "stack-files",
                        "command": "test -f apps/ems-stack/docker-compose.yml && test -f apps/ems-stack/nginx/nginx.conf",
                        "cwd": ".",
                    },
                    {
                        "name": "stack-verify",
                        "command": "bash apps/ems-stack/scripts/verify.sh",
                        "cwd": ".",
                    },
                ],
                "depends_on": ["ems-api-scaffold", "ems-ui-scaffold"],
                "labels": ["deploy", "local", "compose"],
            },
            {
                "id": "ems-dns-route53",
                "title": "Route53 DNS stub",
                "description": "Add Route53 integration placeholder for subdomain creation.",
                "type": "integration",
                "repo_targets": [repo_targets[0]],
                "inputs": {"artifacts": ["implementation_plan.json"]},
                "outputs": {
                    "paths": [
                        "apps/ems-api/ems_api/integrations/__init__.py",
                        "apps/ems-api/ems_api/integrations/route53.py",
                        "apps/ems-api/ems_api/tests/test_route53.py",
                    ]
                },
                "acceptance_criteria": [
                    "Route53 module stub exists with create/update function signatures.",
                ],
                "verify": [
                    {"name": "route53-file", "command": "test -f ems_api/integrations/route53.py", "cwd": "apps/ems-api"},
                ],
                "depends_on": ["ems-api-scaffold"],
                "labels": ["dns", "integration"],
            },
            {
                "id": "dns.ensure_record.route53",
                "title": "Ensure Route53 DNS record",
                "description": "Create/ensure Route53 DNS A record for EMS public FQDN.",
                "type": "deploy",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": ".",
                        "auth": "https_token",
                        "allow_write": False,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json", "blueprint_metadata.json"]},
                "outputs": {"paths": [], "artifacts": ["dns_change_result.json"]},
                "acceptance_criteria": ["Route53 record exists for EMS FQDN."],
                "verify": [{"name": "dns-ensure", "command": "echo 'handled by runner'", "cwd": "."}],
                "depends_on": [],
                "labels": ["module", "dns", "module:dns-route53", "capability:dns.route53.records"],
            },
            {
                "id": "deploy.apply_remote_compose.ssm",
                "title": "Remote deploy via SSM",
                "description": "Deploy EMS stack to target instance using SSM and docker-compose.",
                "type": "deploy",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": ".",
                        "auth": "https_token",
                        "allow_write": False,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json", "blueprint_metadata.json"]},
                "outputs": {"paths": [], "artifacts": ["deploy_result.json", "deploy_manifest.json"]},
                "acceptance_criteria": ["EMS stack deployed and healthy on target instance."],
                "verify": [{"name": "remote-deploy", "command": "echo 'handled by runner'", "cwd": "."}],
                "depends_on": ["dns.ensure_record.route53"],
                "labels": ["deploy", "ssm", "remote"],
            },
            {
                "id": "verify.public_http",
                "title": "Verify public EMS health",
                "description": "Verify public HTTP health endpoints on EMS FQDN.",
                "type": "deploy",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": ".",
                        "auth": "https_token",
                        "allow_write": False,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json", "blueprint_metadata.json"]},
                "outputs": {"paths": [], "artifacts": ["deploy_verify.json"]},
                "acceptance_criteria": ["Public /health and /api/health return 200."],
                "verify": [{"name": "public-verify", "command": "echo 'handled by runner'", "cwd": "."}],
                "depends_on": ["deploy.apply_remote_compose.ssm"],
                "labels": ["deploy", "verify", "remote"],
            },
            {
                "id": "tls.acme_http01",
                "title": "ACME TLS bootstrap",
                "description": "Issue or renew TLS certificates via ACME (Let's Encrypt).",
                "type": "deploy",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": ".",
                        "auth": "https_token",
                        "allow_write": False,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json", "blueprint_metadata.json"]},
                "outputs": {"paths": [], "artifacts": ["acme_result.json", "deploy_execution_tls.log"]},
                "acceptance_criteria": ["TLS certificate exists and is valid."],
                "verify": [{"name": "acme-verify", "command": "echo 'handled by runner'", "cwd": "."}],
                "depends_on": ["dns.ensure_record.route53", "deploy.apply_remote_compose.ssm"],
                "labels": ["deploy", "tls", "acme"],
            },
            {
                "id": "ingress.nginx_tls_configure",
                "title": "Configure nginx for TLS",
                "description": "Enable TLS in nginx and reload stack.",
                "type": "deploy",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": ".",
                        "auth": "https_token",
                        "allow_write": False,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json", "blueprint_metadata.json"]},
                "outputs": {"paths": [], "artifacts": ["deploy_execution_tls.log"]},
                "acceptance_criteria": ["nginx serves HTTPS using ACME cert."],
                "verify": [{"name": "tls-nginx", "command": "echo 'handled by runner'", "cwd": "."}],
                "depends_on": ["tls.acme_http01"],
                "labels": ["deploy", "tls", "nginx"],
            },
            {
                "id": "verify.public_https",
                "title": "Verify public HTTPS health",
                "description": "Verify public HTTPS endpoints on EMS FQDN.",
                "type": "deploy",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": ".",
                        "auth": "https_token",
                        "allow_write": False,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json", "blueprint_metadata.json"]},
                "outputs": {"paths": [], "artifacts": ["deploy_verify.json"]},
                "acceptance_criteria": ["Public HTTPS /health and /api/health return 200."],
                "verify": [{"name": "public-verify-https", "command": "echo 'handled by runner'", "cwd": "."}],
                "depends_on": ["ingress.nginx_tls_configure"],
                "labels": ["deploy", "verify", "https"],
            },
        ]
    else:
        functional = [str(item).strip() for item in (intent_requirements.get("functional") or []) if str(item).strip()]
        ui = [str(item).strip() for item in (intent_requirements.get("ui") or []) if str(item).strip()]
        data_model = [str(item).strip() for item in (intent_requirements.get("dataModel") or []) if str(item).strip()]
        operational = [str(item).strip() for item in (intent_requirements.get("operational") or []) if str(item).strip()]
        dod = [str(item).strip() for item in (intent_requirements.get("definitionOfDone") or []) if str(item).strip()]
        summary = str(intent_requirements.get("summary") or "").strip()
        if not summary:
            summary = (intent_prompt or "Create initial scaffold for blueprint.")[:240]

        work_items = []
        if functional:
            work_items.append(
                {
                    "id": f"{blueprint.name}-api-features",
                    "title": f"Implement API features for {blueprint_fqn}",
                    "description": summary,
                    "type": "feature",
                    "repo_targets": repo_targets[:1],
                    "inputs": {"artifacts": ["implementation_plan.json", "blueprint_intent.json"]},
                    "outputs": {"paths": ["services/api/README.md"]},
                    "acceptance_criteria": functional,
                    "verify": [{"name": "api-sanity", "command": "echo 'api checks defined in task output'"}],
                    "depends_on": [],
                    "labels": ["api", "feature", "intent-driven"],
                }
            )
        if ui:
            work_items.append(
                {
                    "id": f"{blueprint.name}-ui-features",
                    "title": f"Implement UI requirements for {blueprint_fqn}",
                    "description": "Implement UI behavior captured in blueprint intent.",
                    "type": "feature",
                    "repo_targets": repo_targets[1:2] or repo_targets[:1],
                    "inputs": {"artifacts": ["implementation_plan.json", "blueprint_intent.json"]},
                    "outputs": {"paths": ["services/web/README.md"]},
                    "acceptance_criteria": ui,
                    "verify": [{"name": "ui-sanity", "command": "echo 'ui checks defined in task output'"}],
                    "depends_on": [work_items[0]["id"]] if work_items else [],
                    "labels": ["ui", "feature", "intent-driven"],
                }
            )
        if data_model:
            work_items.append(
                {
                    "id": f"{blueprint.name}-data-model",
                    "title": f"Implement data model for {blueprint_fqn}",
                    "description": "Establish entities and persistence required by blueprint intent.",
                    "type": "integration",
                    "repo_targets": repo_targets[:1],
                    "inputs": {"artifacts": ["implementation_plan.json", "blueprint_intent.json"]},
                    "outputs": {"paths": ["services/api/migrations/README.md"]},
                    "acceptance_criteria": data_model,
                    "verify": [{"name": "data-sanity", "command": "echo 'data model checks defined in task output'"}],
                    "depends_on": [item["id"] for item in work_items[:1]],
                    "labels": ["data", "schema", "intent-driven"],
                }
            )
        if operational or dod:
            work_items.append(
                {
                    "id": f"{blueprint.name}-operational-hardening",
                    "title": f"Operationalize {blueprint_fqn}",
                    "description": "Apply deployment and operational requirements from blueprint intent.",
                    "type": "deploy",
                    "repo_targets": repo_targets[:1],
                    "inputs": {"artifacts": ["implementation_plan.json", "blueprint_intent.json"]},
                    "outputs": {"paths": ["services/api/ops/README.md"]},
                    "acceptance_criteria": operational + dod,
                    "verify": [{"name": "ops-sanity", "command": "echo 'ops checks defined in task output'"}],
                    "depends_on": [item["id"] for item in work_items],
                    "labels": ["deploy", "ops", "intent-driven"],
                }
            )
        if not work_items:
            work_items = [
                {
                    "id": f"{blueprint.name}-scaffold",
                    "title": f"Scaffold {blueprint_fqn}",
                    "description": summary or "Create initial scaffold for blueprint.",
                    "type": "scaffold",
                    "repo_targets": repo_targets[:1],
                    "inputs": {"artifacts": ["implementation_plan.json"]},
                    "outputs": {"paths": ["apps/ems-api/README.md"]},
                    "acceptance_criteria": ["Scaffold created from blueprint intent."],
                    "verify": [{"name": "scaffold-file", "command": "test -f apps/ems-api/README.md"}],
                    "depends_on": [],
                    "labels": ["scaffold", "intent-driven"],
                }
            ]

    if intent_requirements or intent_prompt:
        _apply_intent_context_to_work_items(work_items, intent_requirements, intent_prompt)

    if module_catalog is None:
        module_catalog = _build_module_catalog()
    if run_history_summary is None:
        run_history_summary = _build_run_history_summary(blueprint, release_target)

    blueprint_spec_json: Dict[str, Any] = {}
    if blueprint.spec_text:
        try:
            parsed_spec = json.loads(blueprint.spec_text)
            if isinstance(parsed_spec, dict):
                blueprint_spec_json = parsed_spec
        except json.JSONDecodeError:
            blueprint_spec_json = {}
    release_spec_payload = (
        blueprint_spec_json.get("releaseSpec")
        if isinstance(blueprint_spec_json.get("releaseSpec"), dict)
        else {}
    )
    release_spec_metadata = (
        release_spec_payload.get("metadata")
        if isinstance(release_spec_payload.get("metadata"), dict)
        else {}
    )
    release_namespace = str(
        release_spec_metadata.get("namespace")
        or blueprint.namespace
        or "core"
    ).strip() or "core"
    release_components = (
        release_spec_payload.get("components")
        if isinstance(release_spec_payload.get("components"), list)
        else []
    )
    release_repo_targets = (
        release_spec_payload.get("repoTargets")
        if isinstance(release_spec_payload.get("repoTargets"), list)
        else []
    )
    if not release_repo_targets and release_components:
        # Backward-compatible default repo target map for generated drafts/specs
        # that do not yet include releaseSpec.repoTargets.
        release_repo_targets = [
            {
                "name": "xyn-api",
                "url": "https://github.com/Xyence/xyn-api",
                "ref": "main",
                "path_root": ".",
                "auth": "https_token",
                "allow_write": False,
            },
            {
                "name": "xyn-ui",
                "url": "https://github.com/Xyence/xyn-ui",
                "ref": "main",
                "path_root": ".",
                "auth": "https_token",
                "allow_write": False,
            },
        ]
    release_repo_targets = [
        _normalize_repo_target_entry(target)
        for target in release_repo_targets
        if isinstance(target, dict) and str(target.get("name") or "").strip()
    ]
    repo_target_map: Dict[str, Dict[str, Any]] = {}
    for target in release_repo_targets:
        if not isinstance(target, dict):
            continue
        normalized = _normalize_repo_target_entry(target)
        target_name = str(normalized.get("name") or "").strip()
        if target_name:
            repo_target_map[target_name] = normalized
    release_image_inputs: List[Dict[str, Any]] = []
    release_build_inputs: List[Dict[str, Any]] = []
    selected_repo_targets: Dict[str, Dict[str, Any]] = {}
    for component in release_components:
        if not isinstance(component, dict):
            continue
        comp_name = str(component.get("name") or "").strip()
        if not comp_name:
            continue
        image_name = re.sub(r"[^a-z0-9._-]+", "-", comp_name.lower()).strip("-") or "component"
        comp_image = str(component.get("image") or "").strip()
        build_cfg = component.get("build") if isinstance(component.get("build"), dict) else {}
        if build_cfg:
            repo_target_name = str(
                build_cfg.get("repoTarget")
                or component.get("repoTarget")
                or ""
            ).strip()
            selected_repo_target: Optional[Dict[str, Any]] = None
            if repo_target_name:
                selected_repo_target = repo_target_map.get(repo_target_name)
                if not selected_repo_target:
                    raise RuntimeError(
                        f"component {comp_name} has build config but repoTarget '{repo_target_name}' is not defined in releaseSpec.repoTargets"
                    )
            elif len(repo_target_map) > 1:
                # Heuristic fallback for generated drafts that omit explicit repoTarget.
                # Keeps planner resilient while still deterministic.
                context_hint = str(build_cfg.get("context") or "").strip().lower()
                preferred_name = _guess_repo_target_name_for_component(
                    comp_name=comp_name,
                    context_hint=context_hint,
                    repo_target_map=repo_target_map,
                )
                if preferred_name and preferred_name in repo_target_map:
                    repo_target_name = preferred_name
                    selected_repo_target = repo_target_map.get(repo_target_name)
            elif len(repo_target_map) == 1 and str(build_cfg.get("context") or "").strip().startswith("services/"):
                # Fallback for simple single-repo blueprints.
                repo_target_name, selected_repo_target = next(iter(repo_target_map.items()))
            else:
                raise RuntimeError(
                    f"component {comp_name} has build config but no repoTarget mapping. Add releaseSpec.repoTargets and component.build.repoTarget."
                )
            build_context = str(build_cfg.get("context") or "").strip()
            if not build_context:
                raise RuntimeError(f"component {comp_name} build.context is required")
            dockerfile_path = str(build_cfg.get("dockerfile") or "Dockerfile").strip()
            image_name_override = str(build_cfg.get("imageName") or image_name).strip()
            build_entry: Dict[str, Any] = {
                "name": image_name_override,
                "service": comp_name,
                "repo": repo_target_name,
                "context_path": build_context,
                "dockerfile_path": dockerfile_path,
            }
            if build_cfg.get("target"):
                build_entry["target"] = str(build_cfg.get("target"))
            if isinstance(build_cfg.get("args"), dict):
                build_entry["build_args"] = build_cfg.get("args")
            release_build_inputs.append(build_entry)
            selected_repo_targets[repo_target_name] = _ensure_repo_target_complete(
                selected_repo_target or {},
                context=f"component {comp_name} repoTarget '{repo_target_name}'",
            )
            continue
        if comp_image:
            release_image_inputs.append(
                {
                    "name": image_name,
                    "service": comp_name,
                    "image_uri": comp_image,
                }
            )

    module_ids = {entry.get("id") for entry in module_catalog.get("modules", [])}
    metadata = blueprint.metadata_json or {}
    modules_required = metadata.get("modules_required") or []
    if isinstance(modules_required, str):
        modules_required = [modules_required]
    dns_provider = metadata.get("dns_provider")
    release_dns = release_target.get("dns") if isinstance(release_target, dict) else {}
    release_runtime = release_target.get("runtime") if isinstance(release_target, dict) else {}
    release_tls = release_target.get("tls") if isinstance(release_target, dict) else {}
    image_deploy_enabled = _normalize_runtime_mode(release_runtime) == "compose_images"
    if release_dns:
        dns_provider = release_dns.get("provider") or dns_provider
    route53_requested = dns_provider == "route53" or "dns-route53" in modules_required
    deploy_ssm_requested = "deploy-ssm-compose" in modules_required
    tls_acme_requested = any(module in modules_required for module in ("ingress-nginx-acme", "ingress-traefik-acme"))
    runtime_requested = "runtime-web-static-nginx" in modules_required
    image_deploy_requested = image_deploy_enabled or "build-container-publish" in modules_required or "runtime-compose-pull-apply" in modules_required
    if not runtime_requested:
        try:
            metadata_blob = json.dumps(metadata).lower()
        except TypeError:
            metadata_blob = str(metadata).lower()
        runtime_requested = (
            ("docker-compose" in metadata_blob or "compose" in metadata_blob)
            and "nginx" in metadata_blob
            and ("react" in metadata_blob or "vite" in metadata_blob)
        )
    if not deploy_ssm_requested:
        deploy_meta = metadata.get("deploy") or {}
        if release_target:
            deploy_ssm_requested = bool(release_target.get("target_instance_id") and release_target.get("fqdn"))
        else:
            deploy_ssm_requested = bool(deploy_meta.get("target_instance") or deploy_meta.get("target_instance_id"))
        if not deploy_ssm_requested:
            try:
                metadata_blob = json.dumps(metadata).lower()
            except TypeError:
                metadata_blob = str(metadata).lower()
            deploy_ssm_requested = "ssm" in metadata_blob
    tls_meta = release_tls or (metadata.get("tls") or {})
    tls_mode = str(tls_meta.get("mode") or "").lower()
    preferred_ingress_module = "ingress-traefik-acme" if tls_mode == "host-ingress" else "ingress-nginx-acme"
    if not tls_acme_requested:
        tls_acme_requested = tls_mode in {"nginx+acme", "acme", "letsencrypt", "host-ingress"}
    if route53_requested and not any(item.get("id") == "dns.ensure_record.route53" for item in work_items):
        work_items.append(
            {
                "id": "dns.ensure_record.route53",
                "title": "Ensure Route53 DNS record",
                "description": "Ensure the public hostname resolves to the target instance via Route53.",
                "type": "deploy",
                "repo_targets": [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": ".",
                        "auth": "https_token",
                        "allow_write": False,
                    }
                ],
                "inputs": {"artifacts": ["implementation_plan.json", "release_target.json"]},
                "outputs": {"paths": [], "artifacts": ["dns_change_result.json"]},
                "acceptance_criteria": ["DNS record exists and resolves to target public IP."],
                "verify": [{"name": "dns-ensure", "command": "echo 'handled by runner'", "cwd": "."}],
                "depends_on": [],
                "labels": ["deploy", "dns", "module:dns-route53", "capability:dns.route53.records"],
            }
        )
    if image_deploy_enabled:
        work_items = [item for item in work_items if item.get("id") != "deploy.apply_remote_compose.ssm"]
        for item in work_items:
            if "depends_on" in item:
                item["depends_on"] = [
                    "deploy.apply_remote_compose.pull" if dep == "deploy.apply_remote_compose.ssm" else dep
                    for dep in item["depends_on"]
                ]
        build_present = any(
            item.get("id") in {"build.publish_images.container", "build.publish_images.components"}
            for item in work_items
        )
        if not manifest_override and not build_present:
            build_images = release_build_inputs + release_image_inputs
            build_repo_targets = list(selected_repo_targets.values())
            build_id = "build.publish_images.components"
            if release_build_inputs and not build_repo_targets:
                raise RuntimeError("build.publish_images.components requires non-empty repo_targets")
            if release_image_inputs and not release_build_inputs:
                build_id = "build.publish_images.container"
                if isinstance(release_repo_targets, list) and release_repo_targets:
                    build_repo_targets = [target for target in release_repo_targets if isinstance(target, dict)]
                if not build_repo_targets:
                    build_repo_targets = [
                        {
                            "name": "xyn-api",
                            "url": "https://github.com/Xyence/xyn-api",
                            "ref": "main",
                            "path_root": ".",
                            "auth": "https_token",
                            "allow_write": False,
                        }
                    ]
            if not build_images:
                # Backward-compatible EMS fallback when blueprint does not define releaseSpec.components.
                build_images = [
                    {
                        "name": "ems-api",
                        "service": "ems-api",
                        "repo": "xyn-api",
                        "context_path": "apps/ems-api",
                        "dockerfile_path": "apps/ems-api/Dockerfile",
                    },
                    {
                        "name": "ems-web",
                        "service": "ems-web",
                        "repo": "xyn-ui",
                        "context_path": "apps/ems-ui",
                        "dockerfile_path": "apps/ems-ui/Dockerfile",
                    },
                ]
                build_repo_targets = [
                    {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": ".",
                        "auth": "https_token",
                        "allow_write": False,
                    },
                    {
                        "name": "xyn-ui",
                        "url": "https://github.com/Xyence/xyn-ui",
                        "ref": "main",
                        "path_root": ".",
                        "auth": "https_token",
                        "allow_write": False,
                    },
                ]
                build_id = "build.publish_images.container"
            build_repo_targets = [
                _ensure_repo_target_complete(target, context=f"build repo_target[{index}]")
                for index, target in enumerate(build_repo_targets)
            ]
            work_items.append(
                {
                    "id": build_id,
                    "title": "Build and publish container images",
                    "description": "Build or resolve container images and publish release artifacts.",
                    "type": "deploy",
                    "repo_targets": build_repo_targets,
                    "inputs": {"artifacts": ["implementation_plan.json", "release_target.json"]},
                    "outputs": {"paths": [], "artifacts": ["build_result.json", "release_manifest.json"]},
                    "acceptance_criteria": ["Images are built and pushed to registry with digests."],
                    "verify": [{"name": "build-publish", "command": "echo 'handled by runner'", "cwd": "."}],
                    "depends_on": [],
                    "labels": ["deploy", "build", "publish", "module:build-container-publish"],
                    "config": {
                        "images": build_images,
                        "release_components": release_components,
                        "blueprint_id": str(blueprint.id),
                        "blueprint_namespace": release_namespace,
                        "blueprint_repo_slug": str(getattr(blueprint, "repo_slug", "") or "") or slugify(blueprint.name or "") or "blueprint",
                    },
                }
            )
        build_present = any(
            item.get("id") in {"build.publish_images.container", "build.publish_images.components"}
            for item in work_items
        )
        if not any(item.get("id") == "release.validate_manifest.pinned" for item in work_items):
            work_items.append(
                {
                    "id": "release.validate_manifest.pinned",
                    "title": "Validate release manifest pinning",
                    "description": "Ensure release manifest images include pinned digests.",
                    "type": "deploy",
                    "repo_targets": [
                        {
                            "name": "xyn-api",
                            "url": "https://github.com/Xyence/xyn-api",
                            "ref": "main",
                            "path_root": ".",
                            "auth": "https_token",
                            "allow_write": False,
                        }
                    ],
                    "inputs": {"artifacts": ["release_manifest.json", "release_target.json"]},
                    "outputs": {"paths": [], "artifacts": ["validation_result.json"]},
                    "acceptance_criteria": ["Release manifest uses digest-pinned images."],
                    "verify": [{"name": "validate-manifest", "command": "echo 'handled by runner'", "cwd": "."}],
                    "depends_on": (
                        [
                            "build.publish_images.components"
                            if any(item.get("id") == "build.publish_images.components" for item in work_items)
                            else "build.publish_images.container"
                        ]
                        if build_present
                        else []
                    ),
                    "labels": ["deploy", "validate", "release"],
                }
            )
        if not any(item.get("id") == "deploy.apply_remote_compose.pull" for item in work_items):
            work_items.append(
                {
                    "id": "deploy.apply_remote_compose.pull",
                    "title": "Remote deploy via compose pull",
                    "description": "Deploy EMS stack via compose pull/apply using published images.",
                    "type": "deploy",
                    "repo_targets": [
                        {
                            "name": "xyn-api",
                            "url": "https://github.com/Xyence/xyn-api",
                            "ref": "main",
                            "path_root": ".",
                            "auth": "https_token",
                            "allow_write": False,
                        }
                    ],
                    "inputs": {
                        "artifacts": ["implementation_plan.json", "release_target.json", "release_manifest.json"]
                    },
                    "outputs": {"paths": [], "artifacts": ["deploy_result.json", "deploy_manifest.json"]},
                    "acceptance_criteria": ["EMS stack deployed via image pull."],
                    "verify": [{"name": "remote-deploy", "command": "echo 'handled by runner'", "cwd": "."}],
                    "depends_on": ["dns.ensure_record.route53", "release.validate_manifest.pinned"],
                    "labels": ["deploy", "ssm", "remote", "module:runtime-compose-pull-apply"],
                }
            )
    if route53_requested and "dns-route53" not in module_ids:
        if not any(item.get("id") == "dns-route53-module" for item in work_items):
            work_items.insert(
                0,
                {
                    "id": "dns-route53-module",
                    "title": "Route53 module scaffold",
                    "description": "Register Route53 DNS module spec in the local registry.",
                    "type": "scaffold",
                    "repo_targets": [
                        {
                            "name": "xyn-api",
                            "url": "https://github.com/Xyence/xyn-api",
                            "ref": "main",
                            "path_root": "backend/registry/modules",
                            "auth": "https_token",
                            "allow_write": True,
                        }
                    ],
                    "inputs": {"artifacts": ["implementation_plan.json"]},
                    "outputs": {"paths": ["backend/registry/modules/dns-route53.json"]},
                    "acceptance_criteria": ["Route53 module spec exists in module registry."],
                    "verify": [
                        {
                            "name": "module-spec",
                            "command": "test -f backend/registry/modules/dns-route53.json",
                            "cwd": ".",
                        }
                    ],
                    "depends_on": [],
                    "labels": ["module", "dns", "module:dns-route53", "capability:dns.route53.records"],
                },
            )
    if deploy_ssm_requested and "deploy-ssm-compose" not in module_ids:
        if not any(item.get("id") == "deploy-ssm-compose-module" for item in work_items):
            work_items.insert(
                0,
                {
                    "id": "deploy-ssm-compose-module",
                    "title": "SSM compose deploy module scaffold",
                    "description": "Register SSM docker-compose deploy module spec in the local registry.",
                    "type": "scaffold",
                    "repo_targets": [
                        {
                            "name": "xyn-api",
                            "url": "https://github.com/Xyence/xyn-api",
                            "ref": "main",
                            "path_root": "backend/registry/modules",
                            "auth": "https_token",
                            "allow_write": True,
                        }
                    ],
                    "inputs": {"artifacts": ["implementation_plan.json"]},
                    "outputs": {"paths": ["backend/registry/modules/deploy-ssm-compose.json"]},
                    "acceptance_criteria": ["Deploy SSM compose module spec exists in module registry."],
                    "verify": [
                        {
                            "name": "module-spec",
                            "command": "test -f backend/registry/modules/deploy-ssm-compose.json",
                            "cwd": ".",
                        }
                    ],
                    "depends_on": [],
                    "labels": [
                        "module",
                        "deploy",
                        "module:deploy-ssm-compose",
                        "capability:runtime.compose.apply_remote",
                    ],
                },
            )
    ingress_module_item_id = f"{preferred_ingress_module}-module"
    ingress_module_spec_path = f"backend/registry/modules/{preferred_ingress_module}.json"
    ingress_module_title = (
        "Ingress traefik ACME module scaffold"
        if preferred_ingress_module == "ingress-traefik-acme"
        else "Ingress nginx ACME module scaffold"
    )
    ingress_module_description = (
        "Register Traefik+ACME ingress module spec in the local registry."
        if preferred_ingress_module == "ingress-traefik-acme"
        else "Register nginx+ACME ingress module spec in the local registry."
    )
    if tls_acme_requested and preferred_ingress_module not in module_ids:
        if not any(item.get("id") == ingress_module_item_id for item in work_items):
            work_items.insert(
                0,
                {
                    "id": ingress_module_item_id,
                    "title": ingress_module_title,
                    "description": ingress_module_description,
                    "type": "scaffold",
                    "repo_targets": [
                        {
                            "name": "xyn-api",
                            "url": "https://github.com/Xyence/xyn-api",
                            "ref": "main",
                            "path_root": "backend/registry/modules",
                            "auth": "https_token",
                            "allow_write": True,
                        }
                    ],
                    "inputs": {"artifacts": ["implementation_plan.json"]},
                    "outputs": {"paths": [ingress_module_spec_path]},
                    "acceptance_criteria": [f"Ingress module spec {preferred_ingress_module} exists in module registry."],
                    "verify": [
                        {
                            "name": "module-spec",
                            "command": f"test -f {ingress_module_spec_path}",
                            "cwd": ".",
                        }
                    ],
                    "depends_on": [],
                    "labels": [
                        "module",
                        "ingress",
                        f"module:{preferred_ingress_module}",
                        "capability:ingress.tls.acme_http01",
                    ],
                },
            )
    if image_deploy_requested and "build-container-publish" not in module_ids:
        if not any(item.get("id") == "build-container-publish-module" for item in work_items):
            work_items.insert(
                0,
                {
                    "id": "build-container-publish-module",
                    "title": "Container build/publish module scaffold",
                    "description": "Register container build/publish module spec in the local registry.",
                    "type": "scaffold",
                    "repo_targets": [
                        {
                            "name": "xyn-api",
                            "url": "https://github.com/Xyence/xyn-api",
                            "ref": "main",
                            "path_root": "backend/registry/modules",
                            "auth": "https_token",
                            "allow_write": True,
                        }
                    ],
                    "inputs": {"artifacts": ["implementation_plan.json"]},
                    "outputs": {"paths": ["backend/registry/modules/build-container-publish.json"]},
                    "acceptance_criteria": ["Build/publish module spec exists in module registry."],
                    "verify": [
                        {
                            "name": "module-spec",
                            "command": "test -f backend/registry/modules/build-container-publish.json",
                            "cwd": ".",
                        }
                    ],
                    "depends_on": [],
                    "labels": [
                        "module",
                        "build",
                        "module:build-container-publish",
                        "capability:build.container.image",
                    ],
                },
            )
    if image_deploy_requested and "runtime-compose-pull-apply" not in module_ids:
        if not any(item.get("id") == "runtime-compose-pull-apply-module" for item in work_items):
            work_items.insert(
                0,
                {
                    "id": "runtime-compose-pull-apply-module",
                    "title": "Compose pull/apply module scaffold",
                    "description": "Register compose pull/apply module spec in the local registry.",
                    "type": "scaffold",
                    "repo_targets": [
                        {
                            "name": "xyn-api",
                            "url": "https://github.com/Xyence/xyn-api",
                            "ref": "main",
                            "path_root": "backend/registry/modules",
                            "auth": "https_token",
                            "allow_write": True,
                        }
                    ],
                    "inputs": {"artifacts": ["implementation_plan.json"]},
                    "outputs": {"paths": ["backend/registry/modules/runtime-compose-pull-apply.json"]},
                    "acceptance_criteria": ["Compose pull/apply module spec exists in module registry."],
                    "verify": [
                        {
                            "name": "module-spec",
                            "command": "test -f backend/registry/modules/runtime-compose-pull-apply.json",
                            "cwd": ".",
                        }
                    ],
                    "depends_on": [],
                    "labels": [
                        "module",
                        "deploy",
                        "module:runtime-compose-pull-apply",
                        "capability:runtime.compose.pull_apply_remote",
                    ],
                },
            )

    for item in work_items:
        inputs = item.setdefault("inputs", {})
        artifacts = inputs.setdefault("artifacts", [])
        for artifact_name in ("module_catalog.v1.json", "run_history_summary.v1.json"):
            if artifact_name not in artifacts:
                artifacts.append(artifact_name)
        if release_target and "release_target.json" not in artifacts:
            artifacts.append("release_target.json")
        if item.get("id") in {"build.publish_images.container", "build.publish_images.components"}:
            config = item.setdefault("config", {})
            config.setdefault("release_version", planned_release_version)
            config.setdefault("blueprint_id", str(blueprint.id))
            config.setdefault("blueprint_namespace", release_namespace)
            config.setdefault(
                "blueprint_repo_slug",
                str(getattr(blueprint, "repo_slug", "") or "") or slugify(blueprint.name or "") or "blueprint",
            )

    plan_rationale = {"gaps_detected": [], "modules_selected": [], "why_next": ["Default plan generated."]}
    if run_history_summary.get("acceptance_checks_status"):
        work_items, plan_rationale = _select_next_slice(blueprint, work_items, run_history_summary, release_target)

    _annotate_work_items(work_items, module_catalog, preferred_ingress_module=preferred_ingress_module)
    modules_selected = sorted(
        {
            ref.get("id")
            for item in work_items
            for ref in item.get("module_refs", [])
            if isinstance(ref, dict) and ref.get("id")
        }
    )
    if modules_selected:
        plan_rationale["modules_selected"] = modules_selected
    if route53_requested and "dns-route53" not in plan_rationale.get("modules_selected", []):
        plan_rationale.setdefault("modules_selected", []).append("dns-route53")
    if deploy_ssm_requested and "deploy-ssm-compose" not in plan_rationale.get("modules_selected", []):
        plan_rationale.setdefault("modules_selected", []).append("deploy-ssm-compose")
    if tls_acme_requested and preferred_ingress_module not in plan_rationale.get("modules_selected", []):
        plan_rationale.setdefault("modules_selected", []).append(preferred_ingress_module)
    if runtime_requested and "runtime-web-static-nginx" not in plan_rationale.get("modules_selected", []):
        plan_rationale.setdefault("modules_selected", []).append("runtime-web-static-nginx")

    # Host-ingress uses Traefik-managed TLS; remove nginx/acme task path entirely.
    if tls_mode == "host-ingress":
        removed_ids = {"tls.acme_http01", "ingress.nginx_tls_configure"}
        work_items = [item for item in work_items if item.get("id") not in removed_ids]
        fallback_dep = None
        if any(item.get("id") == "verify.public_http" for item in work_items):
            fallback_dep = "verify.public_http"
        elif any(item.get("id") == "deploy.apply_remote_compose.pull" for item in work_items):
            fallback_dep = "deploy.apply_remote_compose.pull"
        elif any(item.get("id") == "deploy.apply_remote_compose.ssm" for item in work_items):
            fallback_dep = "deploy.apply_remote_compose.ssm"
        for item in work_items:
            deps = item.get("depends_on")
            if not isinstance(deps, list):
                continue
            filtered = [dep for dep in deps if dep not in removed_ids]
            if item.get("id") == "verify.public_https" and fallback_dep and fallback_dep not in filtered:
                filtered.append(fallback_dep)
            item["depends_on"] = filtered

    tasks = [
        {
            "task_type": "codegen",
            "title": f"Codegen: {item['title']}",
            "context_purpose": item.get("context_purpose_override") or "coder",
            "work_item_id": item["id"],
        }
        for item in work_items
    ]
    tasks.extend(
        [
            {
                "task_type": "release_plan_generate",
                "title": f"Release plan for {blueprint_fqn}",
                "context_purpose": "planner",
            },
            {
                "task_type": "release_spec_generate",
                "title": f"Release spec for {blueprint_fqn}",
                "context_purpose": "planner",
            },
        ]
    )

    plan = {
        "schema_version": "implementation_plan.v1",
        "blueprint_id": str(blueprint.id),
        "blueprint_name": blueprint_fqn,
        "release_version": planned_release_version,
        "generated_at": timezone.now().isoformat(),
        "stack": {"api": "fastapi", "ui": "react"},
        "global_repo_targets": repo_targets,
        "work_items": work_items,
        "tasks": tasks,
        "plan_rationale": plan_rationale,
    }
    if release_target:
        plan["release_target_id"] = release_target.get("id")
        plan["release_target_name"] = release_target.get("name")
        plan["release_target_environment"] = release_target.get("environment")
        plan["release_target_environment_id"] = release_target.get("environment_id")
    if manifest_override:
        plan["manifest_override"] = True
    return plan


def _prune_run_artifacts() -> None:
    retention_days = int(os.environ.get("XYENCE_RUN_ARTIFACT_RETENTION_DAYS", "30"))
    cutoff = timezone.now() - timezone.timedelta(days=retention_days)
    old_artifacts = RunArtifact.objects.filter(created_at__lt=cutoff)
    media_root = os.environ.get("XYENCE_MEDIA_ROOT") or getattr(settings, "MEDIA_ROOT", "/app/media")
    for artifact in old_artifacts:
        if artifact.url and artifact.url.startswith("/media/"):
            file_path = os.path.join(media_root, artifact.url.replace("/media/", ""))
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except OSError:
                pass
        artifact.delete()


def _select_context_packs_for_dev_task(
    purpose: str,
    namespace: Optional[str],
    project_key: Optional[str],
    task_type: Optional[str],
) -> List[ContextPack]:
    return _select_context_packs_deterministic(
        purpose,
        namespace,
        project_key,
        action="dev_task",
        entity_type="dev_task",
        task_type=task_type,
    )


def _queue_dev_tasks_for_plan(
    blueprint: Blueprint,
    run: Run,
    plan: Dict[str, Any],
    namespace: Optional[str],
    project_key: Optional[str],
    release_target: Optional[Dict[str, Any]] = None,
    enqueue_jobs: bool = False,
) -> List[DevTask]:
    tasks = []
    plan_tasks = plan.get("tasks", [])
    metadata = blueprint.metadata_json or {}
    deploy_meta = metadata.get("deploy") or {}
    target_instance = None
    target_instance_id = deploy_meta.get("target_instance_id")
    target_instance_name = deploy_meta.get("target_instance_name")
    target_instance_ref = deploy_meta.get("target_instance") or {}
    if release_target:
        target_instance_id = release_target.get("target_instance_id") or target_instance_id
    if isinstance(target_instance_ref, dict):
        target_instance_id = target_instance_id or target_instance_ref.get("id")
        target_instance_name = target_instance_name or target_instance_ref.get("name")
    if target_instance_id:
        target_instance = ProvisionedInstance.objects.filter(id=target_instance_id).first()
    if not target_instance and target_instance_name:
        target_instance = ProvisionedInstance.objects.filter(name=target_instance_name).first()
    if not plan_tasks and plan.get("work_items"):
        for work_item in plan.get("work_items", []):
            plan_tasks.append(
                {
                    "task_type": "codegen",
                    "title": f"Codegen: {work_item.get('title')}",
                    "context_purpose": work_item.get("context_purpose_override") or "coder",
                    "work_item_id": work_item.get("id"),
                }
            )
    for item in plan_tasks:
        task_type = item.get("task_type") or "codegen"
        title = item.get("title") or f"{task_type} for {plan.get('blueprint')}"
        context_purpose = item.get("context_purpose") or "coder"
        work_item_id = item.get("work_item_id", "")
        attach_instance = work_item_id in {
            "dns-route53-ensure-record",
            "remote-deploy-compose-ssm",
            "remote-deploy-verify-public",
            "tls-acme-bootstrap",
            "tls-nginx-configure",
            "remote-deploy-verify-https",
            "dns.ensure_record.route53",
            "deploy.apply_remote_compose.ssm",
            "deploy.apply_remote_compose.pull",
            "verify.public_http",
            "tls.acme_http01",
            "ingress.nginx_tls_configure",
            "verify.public_https",
        }
        dev_task = DevTask.objects.create(
            title=title,
            task_type=task_type,
            status="queued",
            priority=item.get("priority", 0),
            source_entity_type="blueprint",
            source_entity_id=plan.get("blueprint_id") or blueprint.id,
            source_run=run,
            input_artifact_key="implementation_plan.json",
            work_item_id=work_item_id,
            context_purpose=context_purpose,
            target_instance=target_instance if attach_instance else None,
            created_by=run.created_by,
            updated_by=run.created_by,
        )
        packs = _select_context_packs_for_dev_task(context_purpose, namespace, project_key, task_type)
        if packs:
            dev_task.context_packs.add(*packs)
        tasks.append(dev_task)
        if enqueue_jobs:
            _enqueue_job("xyn_orchestrator.worker_tasks.run_dev_task", str(dev_task.id), "worker")
    return tasks


def _module_from_spec(spec: Dict[str, Any], user) -> Module:
    metadata = spec.get("metadata", {})
    module_spec = spec.get("module", {})
    namespace = metadata.get("namespace", "core")
    name = metadata.get("name", "module")
    fqn = module_spec.get("fqn") or f"{namespace}.{module_spec.get('type','module')}.{name}"
    module, created = Module.objects.get_or_create(
        fqn=fqn,
        defaults={
            "namespace": namespace,
            "name": name,
            "type": module_spec.get("type", "service"),
            "current_version": metadata.get("version", "0.1.0"),
            "latest_module_spec_json": spec,
            "capabilities_provided_json": module_spec.get("capabilitiesProvided", []),
            "interfaces_json": module_spec.get("interfaces", {}),
            "dependencies_json": module_spec.get("dependencies", {}),
            "created_by": user,
            "updated_by": user,
        },
    )
    if not created:
        module.namespace = namespace
        module.name = name
        module.type = module_spec.get("type", module.type)
        module.current_version = metadata.get("version", module.current_version)
        module.latest_module_spec_json = spec
        module.capabilities_provided_json = module_spec.get("capabilitiesProvided", [])
        module.interfaces_json = module_spec.get("interfaces", {})
        module.dependencies_json = module_spec.get("dependencies", {})
        module.updated_by = user
        module.save(
            update_fields=[
                "namespace",
                "name",
                "type",
                "current_version",
                "latest_module_spec_json",
                "capabilities_provided_json",
                "interfaces_json",
                "dependencies_json",
                "updated_by",
                "updated_at",
            ]
        )
    return module


def _bundle_from_spec(spec: Dict[str, Any], user) -> Bundle:
    metadata = spec.get("metadata", {})
    namespace = metadata.get("namespace", "core")
    name = metadata.get("name", "bundle")
    fqn = spec.get("bundleFqn") or f"{namespace}.bundle.{name}"
    bundle, created = Bundle.objects.get_or_create(
        fqn=fqn,
        defaults={
            "namespace": namespace,
            "name": name,
            "current_version": metadata.get("version", "0.1.0"),
            "bundle_spec_json": spec,
            "created_by": user,
            "updated_by": user,
        },
    )
    if not created:
        bundle.namespace = namespace
        bundle.name = name
        bundle.current_version = metadata.get("version", bundle.current_version)
        bundle.bundle_spec_json = spec
        bundle.updated_by = user
        bundle.save(
            update_fields=[
                "namespace",
                "name",
                "current_version",
                "bundle_spec_json",
                "updated_by",
                "updated_at",
            ]
        )
    return bundle


def _capability_from_spec(spec: Dict[str, Any], user=None) -> Capability:
    metadata = spec.get("metadata", {})
    name = metadata.get("name", "capability")
    version = metadata.get("version", "1.0")
    capability, created = Capability.objects.get_or_create(
        name=name,
        defaults={
            "version": version,
            "profiles_json": spec.get("profiles", []),
            "capability_spec_json": spec,
        },
    )
    if not created:
        capability.version = version
        capability.profiles_json = spec.get("profiles", [])
        capability.capability_spec_json = spec
        capability.save(update_fields=["version", "profiles_json", "capability_spec_json", "updated_at"])
    return capability


def _update_session_from_draft(
    session: BlueprintDraftSession,
    draft_json: Dict[str, Any],
    requirements_summary: str,
    validation_errors: List[str],
    suggested_fixes: Optional[List[str]] = None,
) -> None:
    session.current_draft_json = draft_json
    session.requirements_summary = requirements_summary
    session.validation_errors_json = validation_errors or []
    session.suggested_fixes_json = suggested_fixes or []
    session.status = "ready" if not validation_errors else "ready_with_errors"
    session.save(
        update_fields=[
            "current_draft_json",
            "requirements_summary",
            "validation_errors_json",
            "suggested_fixes_json",
            "status",
            "updated_at",
        ]
    )


def _resolve_default_target_environment(value: Any) -> tuple[Optional[str], Optional[Environment]]:
    raw = str(value or "").strip()
    if not raw:
        return None, None
    environment_obj: Optional[Environment] = None
    try:
        parsed_uuid = uuid.UUID(raw)
    except (TypeError, ValueError, AttributeError):
        parsed_uuid = None
    if parsed_uuid:
        environment_obj = Environment.objects.filter(id=parsed_uuid).first()
    if not environment_obj:
        environment_obj = (
            Environment.objects.filter(slug__iexact=raw).first()
            or Environment.objects.filter(name__iexact=raw).first()
        )
    if environment_obj:
        return environment_obj.name, environment_obj
    return raw, None


def _resolve_default_target_instance(
    instance_id: str,
    instance_name: str,
    environment: Optional[Environment],
    environment_name: Optional[str],
) -> Optional[ProvisionedInstance]:
    instance: Optional[ProvisionedInstance] = None
    if instance_id:
        try:
            instance = ProvisionedInstance.objects.filter(id=instance_id).first()
        except (TypeError, ValueError):
            instance = None
    if not instance and instance_name:
        instance = ProvisionedInstance.objects.filter(name=instance_name).order_by("-created_at").first()
    if not instance:
        return None
    if environment and instance.environment_id and instance.environment_id != environment.id:
        return None
    if not environment and environment_name:
        instance_env_name = (instance.environment.name if instance.environment else "").strip()
        if instance_env_name and instance_env_name.lower() != environment_name.lower():
            return None
    return instance


def _selector_from_value(raw: str) -> Dict[str, str]:
    value = (raw or "").strip()
    if not value:
        return {}
    try:
        parsed_uuid = uuid.UUID(value)
        return {"id": str(parsed_uuid)}
    except (ValueError, TypeError):
        pass
    if re.fullmatch(r"[a-z0-9][a-z0-9-]*", value):
        return {"slug": value}
    return {"name": value}


def _is_valid_fqdn(value: str) -> bool:
    host = (value or "").strip().lower()
    if not host or " " in host:
        return False
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", host))


def _extract_release_target_intent_from_text(text: str) -> Optional[Dict[str, Any]]:
    raw_text = str(text or "")
    if not raw_text.strip():
        return None
    env_selector: Dict[str, str] = {}
    instance_selector: Dict[str, str] = {}
    fqdn = ""
    tls_mode = ""
    notes: List[str] = []
    for raw_line in raw_text.splitlines():
        line = re.sub(r"^\s*[\*\-•]\s*", "", raw_line).strip()
        if not line:
            continue
        lowered = line.lower()
        env_match = re.match(r"^(?:target\s+environment|environment|env)\s*:\s*(.+)$", line, flags=re.IGNORECASE)
        if env_match:
            env_selector = _selector_from_value(env_match.group(1).strip())
            continue
        instance_match = re.match(
            r"^(?:deploy\s+to\s+instance|target\s+instance|instance)\s*:\s*(.+)$",
            line,
            flags=re.IGNORECASE,
        )
        if instance_match:
            instance_raw = instance_match.group(1).strip()
            parsed = _selector_from_value(instance_raw)
            if "slug" in parsed and "id" not in parsed:
                parsed = {"name": instance_raw}
            instance_selector = parsed
            continue
        fqdn_match = re.match(r"^(?:public\s+hostname|hostname|fqdn)\s*:\s*(.+)$", line, flags=re.IGNORECASE)
        if fqdn_match:
            candidate = fqdn_match.group(1).strip()
            if _is_valid_fqdn(candidate):
                fqdn = candidate
            continue
        if lowered.startswith(("tls:", "https:", "acme:")):
            if "traefik" in lowered or "host-ingress" in lowered:
                tls_mode = "host-ingress"
            elif "nginx" in lowered and "acme" in lowered:
                tls_mode = "nginx+acme"
            elif "none" in lowered:
                tls_mode = "none"
            notes.append(line)
            continue
        if "platform defaults" in lowered and ("tls" in lowered or "network" in lowered or "service exposure" in lowered):
            if "traefik" in lowered or "host-ingress" in lowered:
                tls_mode = "host-ingress"
            notes.append(line)
    required_hits = sum(1 for item in [env_selector, instance_selector, fqdn] if item)
    if required_hits == 0:
        return None
    confidence = min(1.0, 0.2 + (required_hits / 3.0) * 0.8)
    intent: Dict[str, Any] = {
        "environment_selector": env_selector,
        "target_instance_selector": instance_selector,
        "fqdn": fqdn,
        "confidence": round(confidence, 2),
        "extraction_source": "prompt",
    }
    if tls_mode:
        intent["tls_mode"] = tls_mode
    if notes:
        intent["notes"] = notes
    errors = _validate_schema(intent, "release_target_intent.v1.schema.json")
    if errors:
        return None
    return intent


def _resolve_environment_selector(selector: Dict[str, Any]) -> tuple[Optional[Environment], List[str]]:
    warnings: List[str] = []
    if not isinstance(selector, dict):
        return None, ["environment selector missing"]
    if selector.get("id"):
        env = Environment.objects.filter(id=selector.get("id")).first()
        if env:
            return env, warnings
    for key in ("slug", "name"):
        value = str(selector.get(key) or "").strip()
        if not value:
            continue
        field_name = "slug__iexact" if key == "slug" else "name__iexact"
        matches = list(Environment.objects.filter(**{field_name: value}).order_by("name"))
        if len(matches) == 1:
            return matches[0], warnings
        if len(matches) > 1:
            warnings.append(f"environment selector '{value}' matched multiple environments")
            return None, warnings
    fuzzy = str(selector.get("name") or selector.get("slug") or "").strip()
    if fuzzy:
        matches = list(Environment.objects.filter(Q(name__icontains=fuzzy) | Q(slug__icontains=fuzzy)).order_by("name"))
        if len(matches) == 1:
            return matches[0], warnings
        if len(matches) > 1:
            warnings.append(f"environment selector '{fuzzy}' is ambiguous")
            return None, warnings
    warnings.append("environment could not be resolved")
    return None, warnings


def _resolve_instance_selector(
    selector: Dict[str, Any],
    environment: Optional[Environment],
) -> tuple[Optional[ProvisionedInstance], List[str]]:
    warnings: List[str] = []
    if not isinstance(selector, dict):
        return None, ["instance selector missing"]
    if selector.get("id"):
        instance = ProvisionedInstance.objects.filter(id=selector.get("id")).first()
        if instance:
            if environment and instance.environment_id and instance.environment_id != environment.id:
                return None, [f"instance '{instance.name}' does not belong to environment '{environment.name}'"]
            return instance, warnings
    name = str(selector.get("name") or "").strip()
    if not name:
        warnings.append("instance could not be resolved")
        return None, warnings
    qs = ProvisionedInstance.objects.filter(name__iexact=name).order_by("-created_at")
    if environment:
        scoped = list(qs.filter(environment=environment))
        if len(scoped) == 1:
            return scoped[0], warnings
        if len(scoped) > 1:
            warnings.append(f"instance selector '{name}' is ambiguous in environment '{environment.name}'")
            return None, warnings
    matches = list(qs)
    if len(matches) == 1:
        return matches[0], warnings
    if len(matches) > 1:
        warnings.append(f"instance selector '{name}' matched multiple instances")
        return None, warnings
    warnings.append(f"instance '{name}' not found")
    return None, warnings


def _resolve_release_target_intent(intent: Dict[str, Any]) -> Dict[str, Any]:
    warnings: List[str] = []
    if not isinstance(intent, dict):
        return {"environment_id": None, "instance_id": None, "warnings": ["intent missing"], "fqdn": None}
    env, env_warnings = _resolve_environment_selector(intent.get("environment_selector") or {})
    warnings.extend(env_warnings)
    instance, instance_warnings = _resolve_instance_selector(intent.get("target_instance_selector") or {}, env)
    warnings.extend(instance_warnings)
    fqdn = str(intent.get("fqdn") or "").strip()
    if fqdn and not _is_valid_fqdn(fqdn):
        warnings.append("fqdn is invalid")
    if not fqdn:
        warnings.append("fqdn missing")
    return {
        "environment_id": str(env.id) if env else None,
        "environment_name": env.name if env else None,
        "instance_id": str(instance.id) if instance else None,
        "instance_name": instance.name if instance else None,
        "fqdn": fqdn or None,
        "warnings": warnings,
    }


def _draft_prompt_text_for_target_extraction(session: BlueprintDraftSession) -> str:
    parts: List[str] = []
    if (session.initial_prompt or "").strip():
        parts.append((session.initial_prompt or "").strip())
    for artifact in session.source_artifacts or []:
        if not isinstance(artifact, dict):
            continue
        artifact_type = str(artifact.get("type", "")).strip().lower()
        if artifact_type not in {"text", "audio_transcript"}:
            continue
        content = str(artifact.get("content", "")).strip()
        if content:
            parts.append(content)
    links = DraftSessionVoiceNote.objects.filter(draft_session=session).select_related("voice_note__transcript")
    for link in links:
        transcript = getattr(link.voice_note, "transcript", None)
        if transcript and (transcript.transcript_text or "").strip():
            parts.append(transcript.transcript_text.strip())
    unique_parts: List[str] = []
    for value in parts:
        if value not in unique_parts:
            unique_parts.append(value)
    return "\n\n".join(unique_parts).strip()


def _store_extracted_release_target_intent(
    session: BlueprintDraftSession,
    intent: Optional[Dict[str, Any]],
    source_text: str,
) -> None:
    metadata = dict(session.metadata_json or {})
    if intent:
        metadata["extracted_release_target_intent"] = intent
        metadata["extracted_release_target_intent_updated_at"] = timezone.now().isoformat()
        metadata["extracted_release_target_intent_source"] = str(intent.get("extraction_source") or "prompt")
        metadata["extracted_release_target_text_hash"] = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    else:
        metadata.pop("extracted_release_target_intent", None)
        metadata.pop("extracted_release_target_intent_updated_at", None)
        metadata.pop("extracted_release_target_intent_source", None)
        metadata.pop("extracted_release_target_text_hash", None)
    session.metadata_json = metadata
    session.save(update_fields=["metadata_json", "updated_at"])


def _extract_default_release_target_inputs(
    session: BlueprintDraftSession,
) -> tuple[Optional[str], Optional[ProvisionedInstance], Optional[str]]:
    payload = session.submitted_payload_json if isinstance(session.submitted_payload_json, dict) else {}
    release_target = payload.get("release_target") if isinstance(payload.get("release_target"), dict) else {}
    metadata_json = session.metadata_json if isinstance(session.metadata_json, dict) else {}
    extracted_intent = (
        metadata_json.get("extracted_release_target_intent")
        if isinstance(metadata_json.get("extracted_release_target_intent"), dict)
        else {}
    )
    resolved_intent = _resolve_release_target_intent(extracted_intent) if extracted_intent else {}
    draft = session.current_draft_json if isinstance(session.current_draft_json, dict) else {}
    metadata = draft.get("metadata") if isinstance(draft.get("metadata"), dict) else {}
    labels = metadata.get("labels") if isinstance(metadata.get("labels"), dict) else {}

    environment_input = (
        release_target.get("environment")
        or release_target.get("environment_name")
        or resolved_intent.get("environment_id")
        or resolved_intent.get("environment_name")
        or payload.get("environment")
        or payload.get("environment_name")
        or payload.get("environment_id")
        or labels.get("xyn.environment")
        or labels.get("xyn.environment_name")
        or labels.get("xyn.environment_id")
    )
    environment_name, environment_obj = _resolve_default_target_environment(environment_input)

    target_instance_id = str(
        release_target.get("target_instance_id")
        or resolved_intent.get("instance_id")
        or payload.get("target_instance_id")
        or labels.get("xyn.target_instance_id")
        or ""
    ).strip()
    target_instance_name = str(
        release_target.get("target_instance_name")
        or resolved_intent.get("instance_name")
        or payload.get("target_instance_name")
        or payload.get("instance_name")
        or labels.get("xyn.target_instance_name")
        or labels.get("xyn.instance_name")
        or ""
    ).strip()
    target_instance = _resolve_default_target_instance(
        target_instance_id,
        target_instance_name,
        environment_obj,
        environment_name,
    )

    hostname = str(
        release_target.get("fqdn")
        or release_target.get("hostname")
        or resolved_intent.get("fqdn")
        or payload.get("fqdn")
        or payload.get("hostname")
        or labels.get("xyn.fqdn")
        or labels.get("xyn.hostname")
        or ""
    ).strip()
    if hostname and (" " in hostname or "." not in hostname):
        hostname = ""
    return environment_name, target_instance, hostname or None


def ensure_default_release_target(
    blueprint_spec: Blueprint,
    environment: str,
    instance: ProvisionedInstance,
    hostname: str,
    user,
) -> tuple[ReleaseTarget, bool]:
    env_name = str(environment or "").strip()
    if not env_name:
        raise ValueError("environment is required")
    if not instance:
        raise ValueError("instance is required")
    fqdn = str(hostname or "").strip()
    if not fqdn:
        raise ValueError("hostname is required")

    blueprint_slug = slugify(blueprint_spec.name) or "blueprint"
    env_slug = slugify(env_name) or "env"
    target_name = f"{blueprint_slug}-{env_slug}-default"
    project_key = f"{blueprint_spec.namespace}.{blueprint_spec.name}"
    remote_root_slug = re.sub(r"[^a-z0-9]+", "-", project_key.lower()).strip("-") or "default"
    default_remote_root = f"/opt/xyn/apps/{remote_root_slug}"
    ingress_service = "ems-web"
    ingress_port = 8080
    if blueprint_spec.spec_text:
        try:
            parsed_spec = json.loads(blueprint_spec.spec_text)
        except json.JSONDecodeError:
            parsed_spec = {}
        if isinstance(parsed_spec, dict):
            release_spec = parsed_spec.get("releaseSpec")
            components = release_spec.get("components") if isinstance(release_spec, dict) else []
            if isinstance(components, list):
                component_names = {
                    str(component.get("name") or "").strip()
                    for component in components
                    if isinstance(component, dict)
                }
                for candidate in ("web", "frontend", "ui", "ems-web"):
                    if candidate in component_names:
                        ingress_service = candidate
                        break
                for component in components:
                    if not isinstance(component, dict):
                        continue
                    if str(component.get("name") or "").strip() != ingress_service:
                        continue
                    ports = component.get("ports")
                    if isinstance(ports, list):
                        for port in ports:
                            if isinstance(port, dict) and port.get("containerPort"):
                                try:
                                    ingress_port = int(port.get("containerPort"))
                                except Exception:
                                    ingress_port = 8080
                                break
                    break

    with transaction.atomic():
        existing = (
            ReleaseTarget.objects.select_for_update()
            .filter(blueprint=blueprint_spec, environment__iexact=env_name)
            .order_by("-created_at")
            .first()
        )
        if existing:
            if existing.auto_generated:
                existing.name = target_name
                existing.environment = env_name
                existing.target_instance_ref = str(instance.id)
                existing.target_instance = instance
                existing.fqdn = fqdn
                existing.dns_json = {"provider": "route53", "ttl": 60}
                existing.runtime_json = {
                    "type": "docker-compose",
                    "transport": "ssm",
                    "mode": "compose_images",
                    "remote_root": default_remote_root,
                    "registry": {
                        "provider": "ecr",
                        "region": instance.aws_region,
                        "repository_prefix": "xyn",
                        "naming_strategy": "ns_blueprint_component",
                        "ensure_repo_exists": True,
                    },
                }
                existing.tls_json = {
                    "mode": "host-ingress",
                    "provider": "traefik",
                    "termination": "host",
                    "acme_email": os.environ.get("XYENCE_ACME_EMAIL", "admin@xyence.io"),
                    "expose_http": True,
                    "expose_https": True,
                    "redirect_http_to_https": True,
                }
                existing.config_json = {
                    **(existing.config_json or {}),
                    "name": target_name,
                    "environment": env_name,
                    "target_instance_id": str(instance.id),
                    "fqdn": fqdn,
                    "dns": {"provider": "route53", "ttl": 60},
                    "runtime": {
                        "type": "docker-compose",
                        "transport": "ssm",
                        "mode": "compose_images",
                        "remote_root": default_remote_root,
                        "registry": {
                            "provider": "ecr",
                            "region": instance.aws_region,
                            "repository_prefix": "xyn",
                            "naming_strategy": "ns_blueprint_component",
                            "ensure_repo_exists": True,
                        },
                    },
                    "tls": existing.tls_json,
                    "ingress": {
                        "network": "xyn-edge",
                        "routes": [
                            {
                                "host": fqdn,
                                "service": ingress_service,
                                "port": ingress_port,
                                "protocol": "http",
                                "health_path": "/health",
                            }
                        ],
                    },
                    "auto_generated": True,
                    "editable": True,
                }
                existing.updated_by = user
                existing.save(
                    update_fields=[
                        "name",
                        "environment",
                        "target_instance_ref",
                        "target_instance",
                        "fqdn",
                        "dns_json",
                        "runtime_json",
                        "tls_json",
                        "config_json",
                        "updated_by",
                        "updated_at",
                    ]
                )
            return existing, False

        target_payload = {
            "name": target_name,
            "environment": env_name,
            "target_instance_id": str(instance.id),
            "fqdn": fqdn,
            "dns": {"provider": "route53", "ttl": 60},
            "runtime": {
                "type": "docker-compose",
                "transport": "ssm",
                "mode": "compose_images",
                "remote_root": default_remote_root,
                "registry": {
                    "provider": "ecr",
                    "region": instance.aws_region,
                    "repository_prefix": "xyn",
                    "naming_strategy": "ns_blueprint_component",
                    "ensure_repo_exists": True,
                },
            },
            "tls": {
                "mode": "host-ingress",
                "provider": "traefik",
                "termination": "host",
                "acme_email": os.environ.get("XYENCE_ACME_EMAIL", "admin@xyence.io"),
                "expose_http": True,
                "expose_https": True,
                "redirect_http_to_https": True,
            },
            "ingress": {
                "network": "xyn-edge",
                "routes": [
                    {
                        "host": fqdn,
                        "service": ingress_service,
                        "port": ingress_port,
                        "protocol": "http",
                        "health_path": "/health",
                    }
                ],
            },
            "env": {},
            "secret_refs": [],
            "auto_generated": True,
            "editable": True,
        }
        target = ReleaseTarget.objects.create(
            blueprint=blueprint_spec,
            name=target_name,
            environment=env_name,
            target_instance_ref=str(instance.id),
            target_instance=instance,
            fqdn=fqdn,
            dns_json=target_payload["dns"],
            runtime_json=target_payload["runtime"],
            tls_json=target_payload["tls"],
            env_json=target_payload["env"],
            secret_refs_json=target_payload["secret_refs"],
            config_json=target_payload,
            auto_generated=True,
            created_by=user,
            updated_by=user,
        )
        logger.info(
            "auto_release_target_created",
            extra={
                "blueprint_spec_id": str(blueprint_spec.id),
                "release_target_id": str(target.id),
                "environment": env_name,
                "instance": str(instance.id),
                "auto_generated": True,
            },
        )
        return target, True


def _publish_draft_session(session: BlueprintDraftSession, user) -> Dict[str, Any]:
    draft = session.current_draft_json
    if not draft:
        return {"ok": False, "error": "No draft to publish.", "validation_errors": []}
    if isinstance(draft, dict) and session.blueprint_kind == "solution":
        draft["intent"] = _build_draft_intent(session, draft)
    errors = _validate_blueprint_spec(draft, session.blueprint_kind)
    if errors:
        return {
            "ok": False,
            "error": "Draft has validation errors; fix before publishing.",
            "validation_errors": errors,
        }
    kind = session.blueprint_kind
    if kind == "solution":
        target_namespace = (session.namespace or "").strip()
        target_project_key = (session.project_key or "").strip()
        target_name = ""
        if target_project_key:
            parts = target_project_key.split(".")
            if len(parts) >= 2:
                target_namespace = parts[0].strip() or target_namespace
                target_name = ".".join(parts[1:]).strip()
            else:
                target_name = target_project_key
        metadata = draft.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        if target_namespace:
            metadata["namespace"] = target_namespace
        if target_name:
            metadata["name"] = target_name
        if metadata:
            draft["metadata"] = metadata
            session.current_draft_json = draft
            session.save(update_fields=["current_draft_json", "updated_at"])

        spec_text = json.dumps(draft, indent=2, ensure_ascii=False)
        metadata_json = draft.get("metadata") if isinstance(draft.get("metadata"), dict) else {}
        blueprint, created = Blueprint.objects.get_or_create(
            name=draft["metadata"]["name"],
            namespace=draft["metadata"].get("namespace", "core"),
            defaults={
                "description": draft.get("description", ""),
                "spec_text": spec_text,
                "metadata_json": metadata_json,
                "created_by": user,
                "updated_by": user,
            },
        )
        if not created:
            blueprint.description = draft.get("description", blueprint.description)
            blueprint.spec_text = spec_text
            blueprint.metadata_json = metadata_json
            blueprint.updated_by = user
            blueprint.save(update_fields=["description", "spec_text", "metadata_json", "updated_by", "updated_at"])
        next_rev = (blueprint.revisions.aggregate(max_rev=models.Max("revision")).get("max_rev") or 0) + 1
        BlueprintRevision.objects.create(
            blueprint=blueprint,
            revision=next_rev,
            spec_json=draft,
            blueprint_kind=kind,
            created_by=user,
        )
        session.linked_blueprint = blueprint
        session.status = "published"
        session.save(update_fields=["linked_blueprint", "status", "updated_at"])
        environment_name, target_instance, hostname = _extract_default_release_target_inputs(session)
        if environment_name and target_instance and hostname:
            environment_slug = slugify(environment_name)
            if environment_slug == "dev":
                try:
                    ensure_default_release_target(
                        blueprint_spec=blueprint,
                        environment=environment_name,
                        instance=target_instance,
                        hostname=hostname,
                        user=user,
                    )
                except Exception:
                    logger.exception(
                        "auto_release_target_create_failed",
                        extra={"blueprint_spec_id": str(blueprint.id), "session_id": str(session.id)},
                    )
        return {
            "ok": True,
            "entity_type": "blueprint",
            "entity_id": str(blueprint.id),
            "revision": next_rev,
        }
    if kind == "module":
        metadata = draft.get("metadata", {})
        module_spec = draft.get("module", {})
        namespace = metadata.get("namespace", "core")
        name = metadata.get("name", "module")
        fqn = module_spec.get("fqn") or f"{namespace}.{module_spec.get('type','module')}.{name}"
        module, created = Module.objects.get_or_create(
            fqn=fqn,
            defaults={
                "namespace": namespace,
                "name": name,
                "type": module_spec.get("type", "service"),
                "current_version": metadata.get("version", "0.1.0"),
                "latest_module_spec_json": draft,
                "capabilities_provided_json": module_spec.get("capabilitiesProvided", []),
                "interfaces_json": module_spec.get("interfaces", {}),
                "dependencies_json": module_spec.get("dependencies", {}),
                "created_by": user,
                "updated_by": user,
            },
        )
        if not created:
            module.namespace = namespace
            module.name = name
            module.type = module_spec.get("type", module.type)
            module.current_version = metadata.get("version", module.current_version)
            module.latest_module_spec_json = draft
            module.capabilities_provided_json = module_spec.get("capabilitiesProvided", [])
            module.interfaces_json = module_spec.get("interfaces", {})
            module.dependencies_json = module_spec.get("dependencies", {})
            module.updated_by = user
            module.save(
                update_fields=[
                    "namespace",
                    "name",
                    "type",
                    "current_version",
                    "latest_module_spec_json",
                    "capabilities_provided_json",
                    "interfaces_json",
                    "dependencies_json",
                    "updated_by",
                    "updated_at",
                ]
            )
        session.status = "published"
        session.save(update_fields=["status", "updated_at"])
        return {"ok": True, "entity_type": "module", "entity_id": str(module.id)}
    if kind == "bundle":
        metadata = draft.get("metadata", {})
        namespace = metadata.get("namespace", "core")
        name = metadata.get("name", "bundle")
        fqn = draft.get("bundleFqn") or f"{namespace}.bundle.{name}"
        bundle, created = Bundle.objects.get_or_create(
            fqn=fqn,
            defaults={
                "namespace": namespace,
                "name": name,
                "current_version": metadata.get("version", "0.1.0"),
                "bundle_spec_json": draft,
                "created_by": user,
                "updated_by": user,
            },
        )
        if not created:
            bundle.namespace = namespace
            bundle.name = name
            bundle.current_version = metadata.get("version", bundle.current_version)
            bundle.bundle_spec_json = draft
            bundle.updated_by = user
            bundle.save(
                update_fields=[
                    "namespace",
                    "name",
                    "current_version",
                    "bundle_spec_json",
                    "updated_by",
                    "updated_at",
                ]
            )
        session.status = "published"
        session.save(update_fields=["status", "updated_at"])
        return {"ok": True, "entity_type": "bundle", "entity_id": str(bundle.id)}
    return {"ok": False, "error": f"Unsupported draft kind: {kind}", "validation_errors": []}


@login_required
def blueprint_list_view(request: HttpRequest) -> HttpResponse:
    if not request.user.is_staff:
        return HttpResponse(status=403)
    blueprints = Blueprint.objects.all().order_by("namespace", "name")
    draft_sessions = BlueprintDraftSession.objects.all().order_by("-updated_at")
    modules = Module.objects.all().order_by("namespace", "name")
    bundles = Bundle.objects.all().order_by("namespace", "name")
    capabilities = Capability.objects.all().order_by("name")
    context_packs = ContextPack.objects.filter(is_active=True).order_by("name")
    return render(
        request,
        "xyn/blueprints_list.html",
        {
            "blueprints": blueprints,
            "draft_sessions": draft_sessions,
            "modules": modules,
            "bundles": bundles,
            "capabilities": capabilities,
            "context_packs": context_packs,
        },
    )


@login_required
def new_draft_session_view(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        name = request.POST.get("name") or f"Blueprint draft {uuid.uuid4()}"
        blueprint_kind = request.POST.get("blueprint_kind", "solution")
        context_pack_ids = request.POST.getlist("context_pack_ids")
        session = BlueprintDraftSession.objects.create(
            name=name,
            blueprint_kind=blueprint_kind,
            context_pack_ids=context_pack_ids,
            created_by=request.user,
            updated_by=request.user,
        )
        resolved = _resolve_context_packs(session, context_pack_ids)
        session.context_pack_refs_json = resolved["refs"]
        session.effective_context_hash = resolved["hash"]
        session.effective_context_preview = resolved["preview"]
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
        return redirect("blueprint-studio", session_id=session.id)
    return redirect("blueprint-list")


@login_required
def blueprint_detail_view(request: HttpRequest, blueprint_id: str) -> HttpResponse:
    if not request.user.is_staff:
        return HttpResponse(status=403)
    blueprint = get_object_or_404(Blueprint, id=blueprint_id)
    revisions = blueprint.revisions.all()
    instances = blueprint.instances.all().order_by("-created_at")
    return render(
        request,
        "xyn/blueprint_detail.html",
        {"blueprint": blueprint, "revisions": revisions, "instances": instances},
    )


@login_required
def module_list_view(request: HttpRequest) -> HttpResponse:
    if not request.user.is_staff:
        return HttpResponse(status=403)
    modules = Module.objects.all().order_by("namespace", "name")
    return render(request, "xyn/modules_list.html", {"modules": modules})


@login_required
def module_detail_view(request: HttpRequest, module_id: str) -> HttpResponse:
    if not request.user.is_staff:
        return HttpResponse(status=403)
    module = get_object_or_404(Module, id=module_id)
    return render(request, "xyn/module_detail.html", {"module": module})


@login_required
def bundle_list_view(request: HttpRequest) -> HttpResponse:
    if not request.user.is_staff:
        return HttpResponse(status=403)
    bundles = Bundle.objects.all().order_by("namespace", "name")
    return render(request, "xyn/bundles_list.html", {"bundles": bundles})


@login_required
def bundle_detail_view(request: HttpRequest, bundle_id: str) -> HttpResponse:
    if not request.user.is_staff:
        return HttpResponse(status=403)
    bundle = get_object_or_404(Bundle, id=bundle_id)
    return render(request, "xyn/bundle_detail.html", {"bundle": bundle})


@login_required
def capability_list_view(request: HttpRequest) -> HttpResponse:
    if not request.user.is_staff:
        return HttpResponse(status=403)
    capabilities = Capability.objects.all().order_by("name")
    return render(request, "xyn/capabilities_list.html", {"capabilities": capabilities})


@login_required
def capability_detail_view(request: HttpRequest, capability_id: str) -> HttpResponse:
    if not request.user.is_staff:
        return HttpResponse(status=403)
    capability = get_object_or_404(Capability, id=capability_id)
    return render(request, "xyn/capability_detail.html", {"capability": capability})


@csrf_exempt
@login_required
def instantiate_blueprint(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    blueprint = get_object_or_404(Blueprint, id=blueprint_id)
    latest_revision = blueprint.revisions.order_by("-revision").first()
    if not latest_revision:
        return JsonResponse({"error": "No revisions available"}, status=400)
    spec = latest_revision.spec_json
    release_spec = spec.get("releaseSpec")
    if not release_spec:
        if _has_release_spec_hints(spec, blueprint):
            release_spec = _default_release_spec_from_hints(spec, blueprint)
        else:
            return JsonResponse(
                {
                    "error": "Blueprint missing releaseSpec and not enough hints to infer a default.",
                    "guidance": {
                        "add_releaseSpec": True,
                        "minimum_example": {
                            "releaseSpec": {
                                "name": f"{blueprint.namespace}.{blueprint.name}",
                                "version": "0.1.0",
                                "modules": [
                                    {"fqn": "core.app-web-stack", "version": "0.1.0"}
                                ],
                            }
                        },
                    },
                },
                status=400,
            )
    payload = {}
    if request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError:
            payload = {}
    if not payload:
        payload = request.POST
    mode = payload.get("mode", "apply")
    release_target_id = payload.get("release_target_id")
    queue_dev_tasks = request.GET.get("queue_dev_tasks") == "1"
    selected_release_target = _select_release_target_for_blueprint(blueprint, release_target_id)
    instance = BlueprintInstance.objects.create(
        blueprint=blueprint,
        revision=latest_revision.revision,
        created_by=request.user,
    )
    run = Run.objects.create(
        entity_type="blueprint",
        entity_id=blueprint.id,
        status="running",
        summary=f"Instantiate {blueprint.namespace}.{blueprint.name}",
        created_by=request.user,
        started_at=timezone.now(),
    )
    context_resolved = _resolve_context_packs(
        session=None,
        selected_ids=None,
        purpose="planner",
        namespace=blueprint.namespace,
        project_key=f"{blueprint.namespace}.{blueprint.name}",
    )
    run.context_pack_refs_json = context_resolved.get("refs", [])
    run.context_hash = context_resolved.get("hash", "")
    _build_context_artifacts(run, context_resolved)
    try:
        run.log_text = "Starting blueprint instantiate\n"
        plan = None
        op = None
        if release_spec:
            safe_release_spec = _sanitize_release_spec_for_xynseed(release_spec)
            plan = _xynseed_request("post", "/releases/plan", {"release_spec": safe_release_spec})
            _write_run_artifact(run, "plan.json", plan, "plan")
            run.log_text += "Release plan created\n"
            if mode == "apply":
                op = _xynseed_request(
                    "post",
                    "/releases/apply",
                    {"release_id": plan.get("releaseId"), "plan_id": plan.get("planId")},
                )
                if op:
                    _write_run_artifact(run, "operation.json", op, "operation")
                    run.log_text += "Release apply executed\n"
            instance.plan_id = plan.get("planId", "")
            instance.release_id = plan.get("releaseId", "")
            if op:
                instance.operation_id = op.get("operationId", "")
                instance.status = "applied" if op.get("status") == "succeeded" else "failed"
            else:
                instance.status = "planned"
            run.metadata_json = {"plan": plan, "operation": op}
            run.status = "succeeded" if instance.status in {"planned", "applied"} else "failed"
        else:
            instance.status = "planned"
            run.status = "succeeded"
        module_catalog = _build_module_catalog()
        _write_run_artifact(run, "module_catalog.v1.json", module_catalog, "module_catalog")
        _write_run_artifact(run, "blueprint_metadata.json", blueprint.metadata_json or {}, "blueprint")
        if selected_release_target:
            release_payload = _release_target_payload(selected_release_target)
            _write_run_artifact(run, "release_target.json", release_payload, "release_target")
        run_history_summary = _build_run_history_summary(blueprint)
        _write_run_artifact(run, "run_history_summary.v1.json", run_history_summary, "run_history_summary")
        implementation_plan = _generate_implementation_plan(
            blueprint,
            module_catalog=module_catalog,
            run_history_summary=run_history_summary,
            release_target=_release_target_payload(selected_release_target) if selected_release_target else None,
            manifest_override=False,
        )
        plan_errors = _validate_schema(implementation_plan, "implementation_plan.v1.schema.json")
        if plan_errors:
            run.log_text += "Implementation plan schema errors:\n"
            for err in plan_errors:
                run.log_text += f"- {err}\n"
            _write_run_artifact(run, "implementation_plan.json", implementation_plan, "implementation_plan")
            _write_run_artifact(run, "implementation_plan.md", "Implementation plan validation failed.", "implementation_plan")
            raise RuntimeError("Implementation plan schema validation failed")
        _write_run_artifact(run, "implementation_plan.json", implementation_plan, "implementation_plan")
        plan_md = (
            f"# Implementation Plan\n\n"
            f"- Blueprint: {implementation_plan['blueprint_name']}\n"
            f"- Generated: {implementation_plan['generated_at']}\n\n"
            "## Work Items\n"
        )
        for item in implementation_plan["work_items"]:
            plan_md += f"- {item['id']}: {item['title']}\n"
        _write_run_artifact(run, "implementation_plan.md", plan_md, "implementation_plan")
        run.log_text += "Implementation plan generated\n"
        if queue_dev_tasks:
            dev_tasks = _queue_dev_tasks_for_plan(
                blueprint=blueprint,
                run=run,
                plan=implementation_plan,
                namespace=blueprint.namespace,
                project_key=f"{blueprint.namespace}.{blueprint.name}",
                release_target=_release_target_payload(selected_release_target) if selected_release_target else None,
                enqueue_jobs=True,
            )
            run.log_text += f"Queued {len(dev_tasks)} dev tasks\n"
    except Exception as exc:
        instance.status = "failed"
        instance.error = str(exc)
        run.status = "failed"
        run.error = str(exc)
        run.log_text = (run.log_text or "") + f"Error: {exc}\n"
    run.finished_at = timezone.now()
    run.save(
        update_fields=[
            "status",
            "error",
            "metadata_json",
            "finished_at",
            "updated_at",
            "log_text",
            "context_pack_refs_json",
            "context_hash",
        ]
    )
    if run.status in {"succeeded", "failed"}:
        _write_run_summary(run)
    instance.save(update_fields=["plan_id", "operation_id", "release_id", "status", "error"])
    return JsonResponse(
        {"instance_id": str(instance.id), "status": instance.status, "run_id": str(run.id)}
    )


@login_required
def blueprint_studio_view(request: HttpRequest, session_id: str) -> HttpResponse:
    if not request.user.is_staff:
        return HttpResponse(status=403)
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    voice_notes = VoiceNote.objects.filter(draftsessionvoicenote__draft_session=session).order_by(
        "draftsessionvoicenote__ordering"
    )
    if not session.context_pack_refs_json:
        resolved = _resolve_context_packs(session)
        session.context_pack_refs_json = resolved["refs"]
        session.effective_context_hash = resolved["hash"]
        session.effective_context_preview = resolved["preview"]
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

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "save_draft":
            raw_json = request.POST.get("draft_json", "")
            try:
                draft_json = json.loads(raw_json)
            except json.JSONDecodeError as exc:
                messages.error(request, f"Draft JSON invalid: {exc}")
            else:
                errors = _validate_blueprint_spec(draft_json, session.blueprint_kind)
                _update_session_from_draft(
                    session,
                    draft_json,
                    session.requirements_summary,
                    errors,
                    suggested_fixes=[],
                )
                messages.success(request, "Draft saved.")
        elif action == "publish":
            _snapshot_draft_session(
                session,
                created_by=request.user,
                note="publish action is deprecated; snapshot saved",
                action="snapshot",
            )
            messages.success(request, "Draft snapshot saved.")

    context = {
        "session": session,
        "voice_notes": voice_notes,
        "draft_json": json.dumps(session.current_draft_json or {}, indent=2),
    }
    return render(request, "xyn/blueprint_studio.html", context)


@csrf_exempt
@login_required
def create_draft_session(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "GET":
        sessions = BlueprintDraftSession.objects.all().order_by("-updated_at", "-created_at")
        if status := (request.GET.get("status") or "").strip():
            sessions = sessions.filter(status=status)
        if kind := (request.GET.get("kind") or request.GET.get("draft_kind") or "").strip().lower():
            if kind not in {"blueprint", "solution"}:
                return JsonResponse({"error": "kind must be blueprint or solution"}, status=400)
            sessions = sessions.filter(draft_kind=kind)
        if namespace := (request.GET.get("namespace") or "").strip():
            sessions = sessions.filter(namespace=namespace)
        if project_key := (request.GET.get("project_key") or "").strip():
            sessions = sessions.filter(project_key=project_key)
        if blueprint_id := (request.GET.get("blueprint_id") or "").strip():
            sessions = sessions.filter(blueprint_id=blueprint_id)
        if query := (request.GET.get("q") or "").strip():
            sessions = sessions.filter(
                Q(title__icontains=query)
                | Q(name__icontains=query)
                | Q(namespace__icontains=query)
                | Q(project_key__icontains=query)
            )
        data = [
            {
                "id": str(session.id),
                "name": session.title or session.name,
                "title": session.title or session.name,
                "kind": session.draft_kind,
                "status": session.status,
                "blueprint_kind": session.blueprint_kind,
                "namespace": session.namespace or None,
                "project_key": session.project_key or None,
                "blueprint_id": str(session.blueprint_id) if session.blueprint_id else None,
                "linked_blueprint_id": str(session.linked_blueprint_id) if session.linked_blueprint_id else None,
                "created_at": session.created_at,
                "updated_at": session.updated_at,
            }
            for session in sessions
        ]
        return JsonResponse({"sessions": data})
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = _safe_json_body(request)
    draft_kind = str(payload.get("kind") or payload.get("draft_kind") or "blueprint").strip().lower()
    if draft_kind not in {"blueprint", "solution"}:
        return JsonResponse({"error": "kind must be blueprint or solution"}, status=400)
    title = (payload.get("title") or payload.get("name") or "").strip() or "Untitled draft"
    blueprint_kind = str(payload.get("blueprint_kind") or "solution")
    namespace = (payload.get("namespace") or "").strip()
    project_key = (payload.get("project_key") or "").strip()
    generate_code = bool(payload.get("generate_code", False))
    initial_prompt = (payload.get("initial_prompt") or "").strip()
    revision_instruction = (payload.get("revision_instruction") or "").strip()
    source_artifacts = _serialize_source_artifacts(payload.get("source_artifacts"))
    context_pack_ids = payload.get("selected_context_pack_ids")
    if context_pack_ids is None:
        context_pack_ids = payload.get("context_pack_ids")
    if context_pack_ids is None:
        context_pack_ids = _recommended_context_pack_ids(
            draft_kind=draft_kind,
            namespace=namespace or None,
            project_key=project_key or None,
            generate_code=generate_code,
        )
    if not isinstance(context_pack_ids, list):
        return JsonResponse({"error": "context_pack_ids must be a list"}, status=400)
    blueprint_id = payload.get("blueprint_id")
    blueprint = None
    if blueprint_id:
        blueprint = Blueprint.objects.filter(id=blueprint_id).first()
        if not blueprint:
            return JsonResponse({"error": "blueprint_id not found"}, status=404)
        namespace = namespace or blueprint.namespace
        project_key = project_key or f"{blueprint.namespace}.{blueprint.name}"
    session = BlueprintDraftSession.objects.create(
        name=title,
        title=title,
        draft_kind=draft_kind,
        blueprint_kind=blueprint_kind,
        blueprint=blueprint,
        namespace=namespace,
        project_key=project_key,
        initial_prompt=initial_prompt,
        revision_instruction=revision_instruction,
        selected_context_pack_ids=context_pack_ids,
        context_pack_ids=context_pack_ids,
        source_artifacts=source_artifacts,
        status="drafting",
        created_by=request.user,
        updated_by=request.user,
    )
    resolved = _resolve_context_packs(
        session,
        context_pack_ids,
        purpose="planner",
        namespace=namespace or None,
        project_key=project_key or None,
    )
    extraction_text = _draft_prompt_text_for_target_extraction(session)
    extracted_intent = _extract_release_target_intent_from_text(extraction_text)
    metadata_json = dict(session.metadata_json or {})
    if extracted_intent:
        metadata_json["extracted_release_target_intent"] = extracted_intent
        metadata_json["extracted_release_target_intent_updated_at"] = timezone.now().isoformat()
        metadata_json["extracted_release_target_intent_source"] = str(extracted_intent.get("extraction_source") or "prompt")
        metadata_json["extracted_release_target_text_hash"] = hashlib.sha256(extraction_text.encode("utf-8")).hexdigest()
    else:
        metadata_json.pop("extracted_release_target_intent", None)
        metadata_json.pop("extracted_release_target_intent_updated_at", None)
        metadata_json.pop("extracted_release_target_intent_source", None)
        metadata_json.pop("extracted_release_target_text_hash", None)
    session.metadata_json = metadata_json
    session.context_pack_refs_json = resolved["refs"]
    session.effective_context_hash = resolved["hash"]
    session.effective_context_preview = resolved["preview"]
    session.context_resolved_at = timezone.now()
    session.save(
        update_fields=[
            "name",
            "title",
            "draft_kind",
            "namespace",
            "project_key",
            "initial_prompt",
            "revision_instruction",
            "selected_context_pack_ids",
            "context_pack_refs_json",
            "effective_context_hash",
            "effective_context_preview",
            "context_resolved_at",
            "metadata_json",
            "updated_at",
        ]
    )
    return JsonResponse(
        {
            "session_id": str(session.id),
            "title": session.title or session.name,
            "kind": session.draft_kind,
            "namespace": session.namespace or None,
            "project_key": session.project_key or None,
            "selected_context_pack_ids": session.selected_context_pack_ids or session.context_pack_ids or [],
        }
    )


@csrf_exempt
@login_required
def list_modules(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
        errors = _validate_blueprint_spec(payload, "module")
        if errors:
            return JsonResponse({"error": "Invalid ModuleSpec", "details": errors}, status=400)
        module = _module_from_spec(payload, request.user)
        return JsonResponse({"id": str(module.id), "fqn": module.fqn})
    qs = Module.objects.all()
    if capability := request.GET.get("capability"):
        qs = qs.filter(capabilities_provided_json__contains=[capability])
    if module_type := request.GET.get("type"):
        qs = qs.filter(type=module_type)
    if namespace := request.GET.get("namespace"):
        qs = qs.filter(namespace=namespace)
    if query := request.GET.get("q"):
        qs = qs.filter(models.Q(name__icontains=query) | models.Q(fqn__icontains=query))
    data = [
        {
            "id": str(module.id),
            "fqn": module.fqn,
            "name": module.name,
            "namespace": module.namespace,
            "type": module.type,
            "current_version": module.current_version,
            "status": module.status,
        }
        for module in qs.order_by("namespace", "name")
    ]
    return JsonResponse({"modules": data})


@login_required
def get_module(request: HttpRequest, module_ref: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    try:
        module = Module.objects.get(id=module_ref)
    except (Module.DoesNotExist, ValueError):
        module = get_object_or_404(Module, fqn=module_ref)
    return JsonResponse(
        {
            "id": str(module.id),
            "fqn": module.fqn,
            "name": module.name,
            "namespace": module.namespace,
            "type": module.type,
            "current_version": module.current_version,
            "status": module.status,
            "module_spec": module.latest_module_spec_json,
        }
    )


@csrf_exempt
@login_required
def list_capabilities(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
        schema = _load_schema("CapabilitySpec.schema.json")
        validator = Draft202012Validator(schema)
        validation_errors = [
            f"{'.'.join(str(p) for p in err.path) if err.path else 'root'}: {err.message}"
            for err in sorted(validator.iter_errors(payload), key=lambda e: e.path)
        ]
        if validation_errors:
            return JsonResponse({"error": "Invalid CapabilitySpec", "details": validation_errors}, status=400)
        capability = _capability_from_spec(payload, request.user)
        return JsonResponse({"id": str(capability.id), "name": capability.name})
    qs = Capability.objects.all()
    if query := request.GET.get("q"):
        qs = qs.filter(name__icontains=query)
    data = [
        {
            "id": str(capability.id),
            "name": capability.name,
            "version": capability.version,
        }
        for capability in qs.order_by("name")
    ]
    return JsonResponse({"capabilities": data})


@login_required
def get_capability(request: HttpRequest, capability_ref: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    try:
        capability = Capability.objects.get(id=capability_ref)
    except (Capability.DoesNotExist, ValueError):
        capability = get_object_or_404(Capability, name=capability_ref)
    return JsonResponse(
        {
            "id": str(capability.id),
            "name": capability.name,
            "version": capability.version,
            "capability_spec": capability.capability_spec_json,
        }
    )


@csrf_exempt
@login_required
def list_bundles(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
        schema = _load_schema("BundleSpec.schema.json")
        validator = Draft202012Validator(schema)
        validation_errors = [
            f"{'.'.join(str(p) for p in err.path) if err.path else 'root'}: {err.message}"
            for err in sorted(validator.iter_errors(payload), key=lambda e: e.path)
        ]
        if validation_errors:
            return JsonResponse({"error": "Invalid BundleSpec", "details": validation_errors}, status=400)
        bundle = _bundle_from_spec(payload, request.user)
        return JsonResponse({"id": str(bundle.id), "fqn": bundle.fqn})
    qs = Bundle.objects.all()
    if namespace := request.GET.get("namespace"):
        qs = qs.filter(namespace=namespace)
    if query := request.GET.get("q"):
        qs = qs.filter(models.Q(name__icontains=query) | models.Q(fqn__icontains=query))
    data = [
        {
            "id": str(bundle.id),
            "fqn": bundle.fqn,
            "name": bundle.name,
            "namespace": bundle.namespace,
            "current_version": bundle.current_version,
            "status": bundle.status,
        }
        for bundle in qs.order_by("namespace", "name")
    ]
    return JsonResponse({"bundles": data})


@login_required
def get_bundle(request: HttpRequest, bundle_ref: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    try:
        bundle = Bundle.objects.get(id=bundle_ref)
    except (Bundle.DoesNotExist, ValueError):
        bundle = get_object_or_404(Bundle, fqn=bundle_ref)
    return JsonResponse(
        {
            "id": str(bundle.id),
            "fqn": bundle.fqn,
            "name": bundle.name,
            "namespace": bundle.namespace,
            "current_version": bundle.current_version,
            "status": bundle.status,
            "bundle_spec": bundle.bundle_spec_json,
        }
    )


def _coerce_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    return value.lower() in {"1", "true", "yes", "y", "on"}


def _safe_json_body(request: HttpRequest) -> Dict[str, Any]:
    if not request.body:
        return {}
    try:
        return json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return {}


def _required_default_pack_names(draft_kind: str, generate_code: bool) -> List[str]:
    names = ["xyn-platform-canon", "xyn-planner-canon"]
    if draft_kind == "solution" or generate_code:
        names.append("xyn-coder-canon")
    return names


def _recommended_context_pack_ids(
    *,
    draft_kind: str,
    namespace: Optional[str],
    project_key: Optional[str],
    generate_code: bool,
) -> List[str]:
    required_names = _required_default_pack_names(draft_kind, generate_code)
    packs = list(ContextPack.objects.filter(is_active=True).order_by("name", "-updated_at"))
    selected: List[ContextPack] = []
    selected_ids: set[str] = set()

    def _pick(name: str, scope: Optional[str] = None, purpose: Optional[List[str]] = None) -> None:
        for pack in packs:
            if pack.name != name:
                continue
            if scope and pack.scope != scope:
                continue
            if purpose and pack.purpose not in purpose:
                continue
            pid = str(pack.id)
            if pid in selected_ids:
                return
            selected_ids.add(pid)
            selected.append(pack)
            return

    # Required global canon packs for planner stage.
    _pick("xyn-platform-canon", scope="global", purpose=["any", "planner"])
    _pick("xyn-planner-canon", scope="global", purpose=["any", "planner"])

    # Scope-matched defaults are driven by ContextPack.is_default metadata.
    if namespace:
        for pack in packs:
            if not pack.is_default:
                continue
            if pack.scope != "namespace" or pack.namespace != namespace:
                continue
            if pack.purpose not in {"any", "planner"}:
                continue
            pid = str(pack.id)
            if pid not in selected_ids:
                selected_ids.add(pid)
                selected.append(pack)

    if project_key:
        for pack in packs:
            if not pack.is_default:
                continue
            if pack.scope != "project" or pack.project_key != project_key:
                continue
            if pack.purpose not in {"any", "planner"}:
                continue
            pid = str(pack.id)
            if pid not in selected_ids:
                selected_ids.add(pid)
                selected.append(pack)

    # Coder canon defaults for solution/generate_code only.
    if draft_kind == "solution" or generate_code:
        _pick("xyn-coder-canon", scope="global", purpose=["any", "coder"])

    # Guard: if a required pack wasn't found by canonical scope constraints, fall back to any active match by name.
    names_present = {pack.name for pack in selected}
    for required in required_names:
        if required in names_present:
            continue
        for pack in packs:
            if pack.name != required:
                continue
            pid = str(pack.id)
            if pid in selected_ids:
                continue
            selected_ids.add(pid)
            selected.append(pack)
            break
    return [str(pack.id) for pack in selected]


def _serialize_context_pack(pack: ContextPack) -> Dict[str, Any]:
    return {
        "id": str(pack.id),
        "name": pack.name,
        "purpose": pack.purpose,
        "scope": pack.scope,
        "namespace": pack.namespace,
        "project_key": pack.project_key,
        "version": pack.version,
        "is_active": pack.is_active,
        "is_default": pack.is_default,
        "updated_at": pack.updated_at,
    }


def _serialize_source_artifacts(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    artifacts: List[Dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        artifact_type = str(item.get("type", "")).strip().lower()
        if artifact_type not in {"text", "audio_transcript"}:
            continue
        content = str(item.get("content", "")).strip()
        if not content:
            continue
        meta = item.get("meta")
        artifacts.append(
            {
                "type": artifact_type,
                "content": content,
                "meta": meta if isinstance(meta, dict) else {},
            }
        )
    return artifacts


def _clear_default_for_scope(scope: str, namespace: str, project_key: str, exclude_id: Optional[str] = None) -> None:
    qs = ContextPack.objects.filter(scope=scope, is_default=True)
    if namespace:
        qs = qs.filter(namespace=namespace)
    if project_key:
        qs = qs.filter(project_key=project_key)
    if exclude_id:
        qs = qs.exclude(id=exclude_id)
    qs.update(is_default=False)


@csrf_exempt
@login_required
def list_context_packs(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
        name = payload.get("name")
        scope = payload.get("scope", "global")
        purpose = payload.get("purpose", "any")
        version = payload.get("version")
        content = payload.get("content_markdown", "")
        if not name or not version or not content:
            return JsonResponse({"error": "name, version, content_markdown required"}, status=400)
        namespace = payload.get("namespace", "")
        project_key = payload.get("project_key", "")
        is_active = bool(payload.get("is_active", True))
        is_default = bool(payload.get("is_default", False))
        if is_default:
            _clear_default_for_scope(scope, namespace, project_key)
        pack = ContextPack.objects.create(
            name=name,
            purpose=purpose,
            scope=scope,
            namespace=namespace,
            project_key=project_key,
            version=version,
            is_active=is_active,
            is_default=is_default,
            content_markdown=content,
            applies_to_json=payload.get("applies_to_json", {}),
            created_by=request.user,
            updated_by=request.user,
        )
        return JsonResponse({"id": str(pack.id)})
    qs = ContextPack.objects.all()
    if scope := request.GET.get("scope"):
        qs = qs.filter(scope=scope)
    if purpose := request.GET.get("purpose"):
        qs = qs.filter(purpose=purpose)
    if namespace := request.GET.get("namespace"):
        qs = qs.filter(namespace=namespace)
    if project_key := request.GET.get("project_key"):
        qs = qs.filter(project_key=project_key)
    if active_param := request.GET.get("active"):
        if (active_val := _coerce_bool(active_param)) is not None:
            qs = qs.filter(is_active=active_val)
    data = [
        {
            "id": str(pack.id),
            "name": pack.name,
            "purpose": pack.purpose,
            "scope": pack.scope,
            "namespace": pack.namespace,
            "project_key": pack.project_key,
            "version": pack.version,
            "is_active": pack.is_active,
            "is_default": pack.is_default,
            "applies_to_json": pack.applies_to_json or {},
            "updated_at": pack.updated_at,
        }
        for pack in qs.order_by("name", "version")
    ]
    return JsonResponse({"context_packs": data})


@login_required
def context_pack_defaults(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    draft_kind = (request.GET.get("draft_kind") or "blueprint").strip().lower()
    if draft_kind not in {"blueprint", "solution"}:
        return JsonResponse({"error": "draft_kind must be blueprint or solution"}, status=400)
    namespace = (request.GET.get("namespace") or "").strip() or None
    project_key = (request.GET.get("project_key") or "").strip() or None
    generate_code = _coerce_bool(request.GET.get("generate_code")) or False
    recommended_ids = _recommended_context_pack_ids(
        draft_kind=draft_kind,
        namespace=namespace,
        project_key=project_key,
        generate_code=generate_code,
    )
    packs = list(ContextPack.objects.filter(id__in=recommended_ids))
    pack_map = {str(pack.id): pack for pack in packs}
    ordered = [pack_map[pack_id] for pack_id in recommended_ids if pack_id in pack_map]
    return JsonResponse(
        {
            "draft_kind": draft_kind,
            "namespace": namespace,
            "project_key": project_key,
            "generate_code": generate_code,
            "recommended_context_pack_ids": recommended_ids,
            "required_pack_names": _required_default_pack_names(draft_kind, generate_code),
            "recommended_context_packs": [_serialize_context_pack(pack) for pack in ordered],
        }
    )


@csrf_exempt
@login_required
def context_pack_detail(request: HttpRequest, pack_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    pack = get_object_or_404(ContextPack, id=pack_id)
    if request.method == "PUT":
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
        pack.name = payload.get("name", pack.name)
        pack.purpose = payload.get("purpose", pack.purpose)
        pack.scope = payload.get("scope", pack.scope)
        pack.namespace = payload.get("namespace", pack.namespace)
        pack.project_key = payload.get("project_key", pack.project_key)
        pack.version = payload.get("version", pack.version)
        pack.content_markdown = payload.get("content_markdown", pack.content_markdown)
        pack.applies_to_json = payload.get("applies_to_json", pack.applies_to_json)
        is_active = payload.get("is_active")
        if is_active is not None:
            pack.is_active = bool(is_active)
        is_default = payload.get("is_default")
        if is_default is not None:
            pack.is_default = bool(is_default)
        if pack.is_default:
            _clear_default_for_scope(pack.scope, pack.namespace, pack.project_key, exclude_id=str(pack.id))
        pack.updated_by = request.user
        pack.save()
    return JsonResponse(
        {
            "id": str(pack.id),
            "name": pack.name,
            "purpose": pack.purpose,
            "scope": pack.scope,
            "namespace": pack.namespace,
            "project_key": pack.project_key,
            "version": pack.version,
            "is_active": pack.is_active,
            "is_default": pack.is_default,
            "content_markdown": pack.content_markdown,
            "applies_to_json": pack.applies_to_json or {},
            "updated_at": pack.updated_at,
        }
    )


@csrf_exempt
@login_required
def context_pack_activate(request: HttpRequest, pack_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    pack = get_object_or_404(ContextPack, id=pack_id)
    pack.is_active = True
    pack.save(update_fields=["is_active", "updated_at"])
    return JsonResponse({"status": "active"})


@csrf_exempt
@login_required
def context_pack_deactivate(request: HttpRequest, pack_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    pack = get_object_or_404(ContextPack, id=pack_id)
    pack.is_active = False
    pack.save(update_fields=["is_active", "updated_at"])
    return JsonResponse({"status": "inactive"})


@csrf_exempt
@login_required
def upload_voice_note(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    audio_file = request.FILES.get("file")
    if not audio_file:
        return JsonResponse({"error": "Missing file"}, status=400)
    session_id = (request.POST.get("session_id") or "").strip()
    if not session_id:
        return JsonResponse({"error": "session_id is required"}, status=400)
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    voice_note = VoiceNote.objects.create(
        title=request.POST.get("title", ""),
        audio_file=audio_file,
        mime_type=request.POST.get("mime_type", ""),
        duration_ms=request.POST.get("duration_ms") or None,
        language_code=request.POST.get("language_code", "en-US"),
        created_by=request.user,
    )
    ordering = DraftSessionVoiceNote.objects.filter(draft_session=session).count()
    DraftSessionVoiceNote.objects.create(
        draft_session=session, voice_note=voice_note, ordering=ordering
    )
    return JsonResponse({"voice_note_id": str(voice_note.id)})


@csrf_exempt
@login_required
def enqueue_transcription(request: HttpRequest, voice_note_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    voice_note = get_object_or_404(VoiceNote, id=voice_note_id)
    mode = _async_mode()
    if mode == "redis":
        voice_note.status = "queued"
        job_id = _enqueue_job("xyn_orchestrator.worker_tasks.transcribe_voice_note", str(voice_note.id))
    else:
        voice_note.status = "transcribing"
        job_id = str(uuid.uuid4())
        _executor.submit(transcribe_voice_note, str(voice_note.id))
    voice_note.job_id = job_id
    voice_note.error = ""
    voice_note.save(update_fields=["status", "job_id", "error"])
    return JsonResponse({"status": voice_note.status, "job_id": job_id})


@csrf_exempt
@login_required
def enqueue_draft_generation(request: HttpRequest, session_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    mode = _async_mode()
    if mode == "redis":
        session.status = "queued"
        job_id = _enqueue_job("xyn_orchestrator.worker_tasks.generate_blueprint_draft", str(session.id))
    else:
        session.status = "drafting"
        job_id = str(uuid.uuid4())
        _executor.submit(generate_blueprint_draft, str(session.id))
    extraction_text = _draft_prompt_text_for_target_extraction(session)
    extracted_intent = _extract_release_target_intent_from_text(extraction_text)
    metadata_json = dict(session.metadata_json or {})
    if extracted_intent:
        metadata_json["extracted_release_target_intent"] = extracted_intent
        metadata_json["extracted_release_target_intent_updated_at"] = timezone.now().isoformat()
        metadata_json["extracted_release_target_intent_source"] = str(extracted_intent.get("extraction_source") or "prompt")
        metadata_json["extracted_release_target_text_hash"] = hashlib.sha256(extraction_text.encode("utf-8")).hexdigest()
    else:
        metadata_json.pop("extracted_release_target_intent", None)
        metadata_json.pop("extracted_release_target_intent_updated_at", None)
        metadata_json.pop("extracted_release_target_intent_source", None)
        metadata_json.pop("extracted_release_target_text_hash", None)
    session.metadata_json = metadata_json
    if _is_draft_context_stale(session):
        resolved = _resolve_context_packs(
            session,
            session.selected_context_pack_ids or session.context_pack_ids or None,
            purpose="planner",
            namespace=session.namespace or None,
            project_key=session.project_key or None,
        )
        session.context_pack_refs_json = resolved["refs"]
        session.effective_context_hash = resolved["hash"]
        session.effective_context_preview = resolved["preview"]
        session.context_resolved_at = timezone.now()
    session.job_id = job_id
    session.last_error = ""
    update_fields = ["status", "job_id", "last_error", "metadata_json"]
    if session.context_resolved_at:
        update_fields.extend(
            ["context_pack_refs_json", "effective_context_hash", "effective_context_preview", "context_resolved_at"]
        )
    if not session.initial_prompt_locked and (session.initial_prompt or "").strip():
        session.initial_prompt_locked = True
        update_fields.append("initial_prompt_locked")
    session.save(update_fields=update_fields)
    return JsonResponse(
        {
            "status": session.status,
            "job_id": job_id,
            "effective_context_hash": session.effective_context_hash,
            "context_resolved_at": session.context_resolved_at.isoformat() if session.context_resolved_at else None,
            "context_stale": _is_draft_context_stale(session),
            "extracted_release_target_intent": extracted_intent,
        }
    )


@csrf_exempt
@login_required
def enqueue_draft_revision(request: HttpRequest, session_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    instruction = ""
    if request.content_type and "application/json" in request.content_type:
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
        instruction = payload.get("instruction", "")
    else:
        instruction = request.POST.get("instruction", "")
    mode = _async_mode()
    if mode == "redis":
        session.status = "queued"
        job_id = _enqueue_job("xyn_orchestrator.worker_tasks.revise_blueprint_draft", str(session.id), instruction)
    else:
        session.status = "drafting"
        job_id = str(uuid.uuid4())
        _executor.submit(revise_blueprint_draft, str(session.id), instruction)
    session.job_id = job_id
    session.last_error = ""
    session.save(update_fields=["status", "job_id", "last_error"])
    return JsonResponse({"status": session.status, "job_id": job_id})


@csrf_exempt
@login_required
def resolve_draft_session_context(request: HttpRequest, session_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    context_pack_ids = payload.get("context_pack_ids")
    if context_pack_ids is not None:
        if not isinstance(context_pack_ids, list):
            return JsonResponse({"error": "context_pack_ids must be a list"}, status=400)
        session.selected_context_pack_ids = context_pack_ids
        session.context_pack_ids = context_pack_ids
    resolved = _resolve_context_packs(session, context_pack_ids)
    extraction_text = _draft_prompt_text_for_target_extraction(session)
    extracted_intent = _extract_release_target_intent_from_text(extraction_text)
    metadata_json = dict(session.metadata_json or {})
    if extracted_intent:
        metadata_json["extracted_release_target_intent"] = extracted_intent
        metadata_json["extracted_release_target_intent_updated_at"] = timezone.now().isoformat()
        metadata_json["extracted_release_target_intent_source"] = str(extracted_intent.get("extraction_source") or "prompt")
        metadata_json["extracted_release_target_text_hash"] = hashlib.sha256(extraction_text.encode("utf-8")).hexdigest()
    else:
        metadata_json.pop("extracted_release_target_intent", None)
        metadata_json.pop("extracted_release_target_intent_updated_at", None)
        metadata_json.pop("extracted_release_target_intent_source", None)
        metadata_json.pop("extracted_release_target_text_hash", None)
    session.metadata_json = metadata_json
    session.context_pack_refs_json = resolved["refs"]
    session.effective_context_hash = resolved["hash"]
    session.effective_context_preview = resolved["preview"]
    session.context_resolved_at = timezone.now()
    session.save(
        update_fields=[
            "context_pack_ids",
            "selected_context_pack_ids",
            "context_pack_refs_json",
            "effective_context_hash",
            "effective_context_preview",
            "context_resolved_at",
            "metadata_json",
            "updated_at",
        ]
    )
    resolved_intent = _resolve_release_target_intent(extracted_intent or {})
    return JsonResponse(
        {
            "context_pack_refs": resolved["refs"],
            "effective_context_hash": resolved["hash"],
            "effective_context_preview": resolved["preview"],
            "context_resolved_at": session.context_resolved_at.isoformat() if session.context_resolved_at else None,
            "context_stale": _is_draft_context_stale(session),
            "selected_context_pack_ids": session.selected_context_pack_ids or session.context_pack_ids or [],
            "extracted_release_target_intent": extracted_intent,
            "extracted_release_target_resolution": resolved_intent,
            "extracted_release_target_warnings": resolved_intent.get("warnings", []),
        }
    )


@csrf_exempt
@login_required
def extract_release_target(request: HttpRequest, session_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    payload = _safe_json_body(request)
    text = str(payload.get("text") or "").strip()
    if not text:
        text = _draft_prompt_text_for_target_extraction(session)
    intent = _extract_release_target_intent_from_text(text)
    _store_extracted_release_target_intent(session, intent, text)
    resolved = _resolve_release_target_intent(intent or {})
    return JsonResponse(
        {
            "intent": intent,
            "resolved": {
                "environment_id": resolved.get("environment_id"),
                "environment_name": resolved.get("environment_name"),
                "instance_id": resolved.get("instance_id"),
                "instance_name": resolved.get("instance_name"),
                "fqdn": resolved.get("fqdn"),
            },
            "warnings": resolved.get("warnings", []),
        }
    )


@csrf_exempt
@login_required
def save_draft_session(request: HttpRequest, session_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    draft_json = payload.get("draft_json")
    if draft_json is None:
        return JsonResponse({"error": "draft_json required"}, status=400)
    if isinstance(draft_json, str):
        try:
            draft_json = json.loads(draft_json)
        except json.JSONDecodeError as exc:
            return JsonResponse({"error": f"draft_json invalid: {exc}"}, status=400)
    if not isinstance(draft_json, dict):
        return JsonResponse({"error": "draft_json must be an object"}, status=400)
    errors = _validate_blueprint_spec(draft_json, session.blueprint_kind)
    _update_session_from_draft(
        session,
        draft_json,
        session.requirements_summary,
        errors,
        suggested_fixes=[],
    )
    session.has_generated_output = bool(draft_json)
    session.save(update_fields=["has_generated_output", "updated_at"])
    _record_draft_session_revision(session, action="save", created_by=request.user)
    return JsonResponse(
        {"status": session.status, "validation_errors": session.validation_errors_json or []}
    )


@csrf_exempt
@login_required
def publish_draft_session(request: HttpRequest, session_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    logger.warning("draft_publish_endpoint_deprecated", extra={"session_id": str(session_id)})
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    payload = _safe_json_body(request)
    snapshot = _snapshot_draft_session(
        session,
        created_by=request.user,
        note=str(payload.get("note") or "").strip() or "publish endpoint alias",
        action="snapshot",
    )
    return JsonResponse(
        {
            "ok": True,
            "deprecated": True,
            "snapshot_id": str(snapshot.id),
            "session_id": str(session.id),
            "status": session.status,
            "updated_at": session.updated_at.isoformat(),
        }
    )


@csrf_exempt
@login_required
def snapshot_draft_session(request: HttpRequest, session_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    payload = _safe_json_body(request)
    snapshot = _snapshot_draft_session(
        session,
        created_by=request.user,
        note=str(payload.get("note") or "").strip() or "manual snapshot",
        action="snapshot",
    )
    return JsonResponse(
        {
            "ok": True,
            "snapshot_id": str(snapshot.id),
            "session_id": str(session.id),
            "status": session.status,
            "updated_at": session.updated_at.isoformat(),
        }
    )


@csrf_exempt
@login_required
def submit_draft_session(request: HttpRequest, session_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    payload = _safe_json_body(request)
    requested_prompt = (payload.get("initial_prompt") or "").strip()
    if session.initial_prompt_locked and requested_prompt and requested_prompt != (session.initial_prompt or "").strip():
        return JsonResponse({"error": "initial_prompt is immutable after first generation"}, status=400)
    initial_prompt = (requested_prompt or session.initial_prompt or "").strip()
    if not initial_prompt:
        return JsonResponse({"error": "initial_prompt is required"}, status=400)
    selected_pack_ids = (
        payload.get("selected_context_pack_ids")
        or session.selected_context_pack_ids
        or session.context_pack_ids
        or []
    )
    if not isinstance(selected_pack_ids, list):
        return JsonResponse({"error": "selected_context_pack_ids must be a list"}, status=400)
    generate_code = bool(payload.get("generate_code", False))
    required_names = _required_default_pack_names(session.draft_kind or "blueprint", generate_code)
    selected_packs = ContextPack.objects.filter(id__in=selected_pack_ids)
    selected_names = {pack.name for pack in selected_packs}
    missing_required = [name for name in required_names if name not in selected_names]
    if missing_required:
        return JsonResponse(
            {"error": "missing required default packs", "required_pack_names": missing_required},
            status=400,
        )
    source_artifacts = session.source_artifacts or []
    if "source_artifacts" in payload:
        source_artifacts = _serialize_source_artifacts(payload.get("source_artifacts"))
    release_target_payload = payload.get("release_target")
    if not isinstance(release_target_payload, dict):
        release_target_payload = {}
    for key in ("environment", "environment_name", "environment_id", "target_instance_id", "target_instance_name", "fqdn", "hostname"):
        if key in payload and key not in release_target_payload:
            release_target_payload[key] = payload.get(key)
    if not release_target_payload:
        metadata_json = session.metadata_json if isinstance(session.metadata_json, dict) else {}
        extracted_intent = (
            metadata_json.get("extracted_release_target_intent")
            if isinstance(metadata_json.get("extracted_release_target_intent"), dict)
            else {}
        )
        if extracted_intent:
            resolved_intent = _resolve_release_target_intent(extracted_intent)
            missing_fields: List[str] = []
            if not resolved_intent.get("environment_id"):
                missing_fields.append("environment")
            if not resolved_intent.get("instance_id"):
                missing_fields.append("target_instance")
            if not resolved_intent.get("fqdn"):
                missing_fields.append("fqdn")
            if missing_fields:
                return JsonResponse(
                    {
                        "error": "release target intent incomplete",
                        "code": "release_target_intent_incomplete",
                        "fields_missing": missing_fields,
                        "warnings": resolved_intent.get("warnings", []),
                        "intent": extracted_intent,
                        "resolved": resolved_intent,
                    },
                    status=400,
                )
            release_target_payload = {
                "environment_id": resolved_intent.get("environment_id"),
                "environment_name": resolved_intent.get("environment_name"),
                "target_instance_id": resolved_intent.get("instance_id"),
                "target_instance_name": resolved_intent.get("instance_name"),
                "fqdn": resolved_intent.get("fqdn"),
            }
    submission_payload = {
        "draft_session_id": str(session.id),
        "kind": session.draft_kind or "blueprint",
        "title": session.title or session.name or "Untitled draft",
        "namespace": session.namespace or None,
        "project_key": session.project_key or None,
        "initial_prompt": initial_prompt,
        "revision_instruction": session.revision_instruction or "",
        "selected_context_pack_ids": selected_pack_ids,
        "source_artifacts": source_artifacts,
        "submitted_at": timezone.now().isoformat(),
    }
    if release_target_payload:
        submission_payload["release_target"] = release_target_payload
    session.initial_prompt = initial_prompt
    session.submitted_payload_json = submission_payload
    session.source_artifacts = source_artifacts
    session.selected_context_pack_ids = selected_pack_ids
    session.context_pack_ids = selected_pack_ids
    session.status = "drafting"
    session.updated_by = request.user
    session.save(
        update_fields=[
            "initial_prompt",
            "source_artifacts",
            "submitted_payload_json",
            "selected_context_pack_ids",
            "context_pack_ids",
            "status",
            "updated_by",
            "updated_at",
        ]
    )
    publish_result = _publish_draft_session(session, request.user)
    if not publish_result.get("ok"):
        return JsonResponse(
            {
                "error": publish_result.get("error", "Submit failed"),
                "validation_errors": publish_result.get("validation_errors", []),
            },
            status=400,
        )
    _record_draft_session_revision(
        session,
        action="submit",
        instruction=session.revision_instruction or "",
        created_by=request.user,
    )
    return JsonResponse(
        {
            "ok": True,
            "status": "submitted",
            "session_id": str(session.id),
            "submission_payload": submission_payload,
            "entity_type": publish_result.get("entity_type"),
            "entity_id": publish_result.get("entity_id"),
            "revision": publish_result.get("revision"),
        }
    )

@login_required
def get_voice_note(request: HttpRequest, voice_note_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    voice_note = get_object_or_404(VoiceNote, id=voice_note_id)
    transcript = getattr(voice_note, "transcript", None)
    return JsonResponse(
        {
            "id": str(voice_note.id),
            "status": voice_note.status,
            "transcript": transcript.transcript_text if transcript else None,
            "job_id": voice_note.job_id,
            "last_error": voice_note.error,
        }
    )


@csrf_exempt
@login_required
def get_draft_session(request: HttpRequest, session_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    if request.method == "DELETE":
        session.delete()
        return JsonResponse({"status": "deleted"})
    if request.method == "PATCH":
        payload = _safe_json_body(request)
        if "title" in payload:
            title = (payload.get("title") or "").strip() or "Untitled draft"
            session.title = title
            session.name = title
        if "kind" in payload or "draft_kind" in payload:
            kind = str(payload.get("kind") or payload.get("draft_kind") or "").strip().lower()
            if kind not in {"blueprint", "solution"}:
                return JsonResponse({"error": "kind must be blueprint or solution"}, status=400)
            session.draft_kind = kind
        if "namespace" in payload:
            session.namespace = (payload.get("namespace") or "").strip()
        if "project_key" in payload:
            session.project_key = (payload.get("project_key") or "").strip()
        if "initial_prompt" in payload:
            next_prompt = (payload.get("initial_prompt") or "").strip()
            if session.initial_prompt_locked and next_prompt != (session.initial_prompt or "").strip():
                return JsonResponse({"error": "initial_prompt is immutable after first generation"}, status=400)
            session.initial_prompt = next_prompt
        if "revision_instruction" in payload:
            session.revision_instruction = (payload.get("revision_instruction") or "").strip()
        if "source_artifacts" in payload:
            session.source_artifacts = _serialize_source_artifacts(payload.get("source_artifacts"))
        selected_ids = payload.get("selected_context_pack_ids")
        if selected_ids is None:
            selected_ids = payload.get("context_pack_ids")
        if selected_ids is not None:
            if not isinstance(selected_ids, list):
                return JsonResponse({"error": "selected_context_pack_ids must be a list"}, status=400)
            session.selected_context_pack_ids = selected_ids
            session.context_pack_ids = selected_ids
            resolved = _resolve_context_packs(
                session,
                selected_ids,
                purpose="planner",
                namespace=session.namespace or None,
                project_key=session.project_key or None,
            )
            session.context_pack_refs_json = resolved["refs"]
            session.effective_context_hash = resolved["hash"]
            session.effective_context_preview = resolved["preview"]
            session.context_resolved_at = timezone.now()
        session.updated_by = request.user
        session.save()
    context_stale = _is_draft_context_stale(session)
    metadata_json = session.metadata_json if isinstance(session.metadata_json, dict) else {}
    extracted_intent = (
        metadata_json.get("extracted_release_target_intent")
        if isinstance(metadata_json.get("extracted_release_target_intent"), dict)
        else None
    )
    extracted_resolution = _resolve_release_target_intent(extracted_intent or {})
    return JsonResponse(
        {
            "id": str(session.id),
            "title": session.title or session.name,
            "kind": session.draft_kind,
            "blueprint_kind": session.blueprint_kind,
            "status": session.status,
            "draft": session.current_draft_json,
            "namespace": session.namespace or None,
            "project_key": session.project_key or None,
            "initial_prompt": session.initial_prompt,
            "initial_prompt_locked": bool(session.initial_prompt_locked),
            "revision_instruction": session.revision_instruction,
            "source_artifacts": session.source_artifacts or [],
            "has_generated_output": bool(session.has_generated_output or session.current_draft_json),
            "requirements_summary": session.requirements_summary,
            "validation_errors": session.validation_errors_json or [],
            "suggested_fixes": session.suggested_fixes_json or [],
            "job_id": session.job_id,
            "last_error": session.last_error,
            "diff_summary": session.diff_summary,
            "context_pack_refs": session.context_pack_refs_json or [],
            "context_pack_ids": session.selected_context_pack_ids or session.context_pack_ids or [],
            "selected_context_pack_ids": session.selected_context_pack_ids or session.context_pack_ids or [],
            "effective_context_hash": session.effective_context_hash,
            "effective_context_preview": session.effective_context_preview,
            "context_resolved_at": session.context_resolved_at.isoformat() if session.context_resolved_at else None,
            "context_stale": context_stale,
            "extracted_release_target_intent": extracted_intent,
            "extracted_release_target_intent_updated_at": metadata_json.get("extracted_release_target_intent_updated_at"),
            "extracted_release_target_intent_source": metadata_json.get("extracted_release_target_intent_source"),
            "extracted_release_target_resolution": extracted_resolution,
            "extracted_release_target_warnings": extracted_resolution.get("warnings", []),
            "created_at": session.created_at,
            "updated_at": session.updated_at,
        }
    )


@login_required
def list_draft_session_revisions(request: HttpRequest, session_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    query = (request.GET.get("q") or "").strip()
    page = max(1, int(request.GET.get("page") or 1))
    page_size = max(1, min(50, int(request.GET.get("page_size") or 5)))
    revisions = DraftSessionRevision.objects.filter(draft_session=session)
    if query:
        revisions = revisions.filter(
            Q(instruction__icontains=query)
            | Q(diff_summary__icontains=query)
            | Q(requirements_summary__icontains=query)
        )
    total = revisions.count()
    start = (page - 1) * page_size
    end = start + page_size
    page_items = revisions.order_by("-revision_number", "-created_at")[start:end]
    return JsonResponse(
        {
            "revisions": [
                {
                    "id": str(item.id),
                    "revision_number": item.revision_number,
                    "action": item.action,
                    "instruction": item.instruction,
                    "created_at": item.created_at.isoformat(),
                    "validation_errors_count": len(item.validation_errors_json or []),
                    "diff_summary": item.diff_summary or "",
                }
                for item in page_items
            ],
            "total": total,
            "page": page,
            "page_size": page_size,
        }
    )


@login_required
def list_draft_session_voice_notes(request: HttpRequest, session_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    links = (
        DraftSessionVoiceNote.objects.filter(draft_session=session)
        .select_related("voice_note", "voice_note__transcript")
        .order_by("ordering")
    )
    data: List[Dict[str, Any]] = []
    for link in links:
        note = link.voice_note
        transcript = getattr(note, "transcript", None)
        data.append(
            {
                "id": str(note.id),
                "title": note.title,
                "status": note.status,
                "created_at": note.created_at,
                "session_id": str(session.id),
                "job_id": note.job_id,
                "last_error": note.error,
                "transcript_text": transcript.transcript_text if transcript else None,
                "transcript_confidence": transcript.confidence if transcript else None,
            }
        )
    return JsonResponse({"voice_notes": data})


@csrf_exempt
def internal_voice_note(request: HttpRequest, voice_note_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    voice_note = get_object_or_404(VoiceNote, id=voice_note_id)
    transcript = getattr(voice_note, "transcript", None)
    return JsonResponse(
        {
            "id": str(voice_note.id),
            "language_code": voice_note.language_code,
            "mime_type": voice_note.mime_type,
            "status": voice_note.status,
            "transcript": transcript.transcript_text if transcript else None,
            "audio_url": f"/xyn/internal/voice-notes/{voice_note.id}/audio",
        }
    )


@csrf_exempt
def internal_voice_note_audio(request: HttpRequest, voice_note_id: str) -> HttpResponse:
    if token_error := _require_internal_token(request):
        return token_error
    voice_note = get_object_or_404(VoiceNote, id=voice_note_id)
    return FileResponse(voice_note.audio_file.open("rb"), content_type=voice_note.mime_type or "application/octet-stream")


@csrf_exempt
def internal_voice_note_transcript(request: HttpRequest, voice_note_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    voice_note = get_object_or_404(VoiceNote, id=voice_note_id)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    transcript_text = payload.get("transcript_text", "")
    confidence = payload.get("confidence")
    raw_response_json = payload.get("raw_response_json")
    VoiceTranscript.objects.update_or_create(
        voice_note=voice_note,
        defaults={
            "provider": payload.get("provider", "google_stt"),
            "transcript_text": transcript_text,
            "confidence": confidence,
            "raw_response_json": raw_response_json,
        },
    )
    voice_note.status = "transcribed"
    voice_note.error = ""
    voice_note.save(update_fields=["status", "error"])
    return JsonResponse({"status": "transcribed"})


@csrf_exempt
def internal_voice_note_error(request: HttpRequest, voice_note_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    voice_note = get_object_or_404(VoiceNote, id=voice_note_id)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    voice_note.status = "failed"
    voice_note.error = payload.get("error", "Unknown error")
    voice_note.save(update_fields=["status", "error"])
    return JsonResponse({"status": "failed"})


@csrf_exempt
def internal_voice_note_status(request: HttpRequest, voice_note_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    voice_note = get_object_or_404(VoiceNote, id=voice_note_id)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    status = payload.get("status")
    if status:
        voice_note.status = status
    voice_note.save(update_fields=["status"])
    return JsonResponse({"status": voice_note.status})


@csrf_exempt
def internal_draft_session(request: HttpRequest, session_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    links = DraftSessionVoiceNote.objects.filter(draft_session=session).select_related("voice_note", "voice_note__transcript").order_by("ordering")
    transcripts = []
    for link in links:
        transcript = getattr(link.voice_note, "transcript", None)
        if transcript:
            transcripts.append(transcript.transcript_text)
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
    combined_prompt = "\n\n".join(ordered_inputs).strip()
    return JsonResponse(
        {
            "id": str(session.id),
            "blueprint_kind": session.blueprint_kind,
            "kind": session.draft_kind,
            "context_pack_ids": session.context_pack_ids or [],
            "selected_context_pack_ids": session.selected_context_pack_ids or session.context_pack_ids or [],
            "initial_prompt": session.initial_prompt,
            "source_artifacts": session.source_artifacts or [],
            "requirements_summary": session.requirements_summary,
            "draft": session.current_draft_json,
            "transcripts": transcripts,
            "combined_prompt": combined_prompt,
        }
    )


@csrf_exempt
def internal_draft_session_context(request: HttpRequest, session_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    resolved = _resolve_context_packs(session)
    session.context_pack_refs_json = resolved["refs"]
    session.effective_context_hash = resolved["hash"]
    session.effective_context_preview = resolved["preview"]
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
    return JsonResponse(
        {
            "effective_context": resolved["effective_context"],
            "context_pack_refs": resolved["refs"],
            "effective_context_hash": resolved["hash"],
            "effective_context_preview": resolved["preview"],
            "context_resolved_at": session.context_resolved_at.isoformat() if session.context_resolved_at else None,
        }
    )


@csrf_exempt
def internal_draft_session_update(request: HttpRequest, session_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    session.current_draft_json = payload.get("draft_json")
    session.requirements_summary = payload.get("requirements_summary", "")
    session.validation_errors_json = payload.get("validation_errors", [])
    session.suggested_fixes_json = payload.get("suggested_fixes", [])
    session.diff_summary = payload.get("diff_summary", "")
    session.status = payload.get("status", session.status)
    session.last_error = payload.get("last_error", "")
    has_draft = bool(payload.get("draft_json"))
    session.has_generated_output = has_draft
    if has_draft and not session.initial_prompt_locked and (session.initial_prompt or "").strip():
        session.initial_prompt_locked = True
    session.save(
        update_fields=[
            "current_draft_json",
            "requirements_summary",
            "validation_errors_json",
            "suggested_fixes_json",
            "diff_summary",
            "status",
            "last_error",
            "has_generated_output",
            "initial_prompt_locked",
            "updated_at",
        ]
    )
    _record_draft_session_revision(
        session,
        action=str(payload.get("action") or "generate").strip().lower(),
        instruction=str(payload.get("instruction") or ""),
        created_by=None,
    )
    return JsonResponse({"status": session.status})


@csrf_exempt
def internal_draft_session_error(request: HttpRequest, session_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    session.status = "failed"
    session.last_error = payload.get("error", "Unknown error")
    session.save(update_fields=["status", "last_error"])
    return JsonResponse({"status": "failed"})


@csrf_exempt
def internal_draft_session_status(request: HttpRequest, session_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    status = payload.get("status")
    if status:
        session.status = status
    session.save(update_fields=["status"])
    return JsonResponse({"status": session.status})


@csrf_exempt
def internal_openai_config(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    from .models import OpenAIConfig

    config = OpenAIConfig.objects.first()
    if not config:
        return JsonResponse({"error": "Missing OpenAI config"}, status=404)
    return JsonResponse(
        {
            "api_key": config.api_key,
            "model": config.default_model,
        }
    )


@csrf_exempt
def internal_run_update(request: HttpRequest, run_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    run = get_object_or_404(Run, id=run_id)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    append_log = payload.pop("append_log", None)
    for field in [
        "status",
        "summary",
        "error",
        "metadata_json",
        "context_pack_refs_json",
        "context_hash",
        "started_at",
        "finished_at",
    ]:
        if field in payload:
            setattr(run, field, payload[field])
    if append_log:
        run.log_text = (run.log_text or "") + append_log
    if run.status == "running" and run.started_at is None:
        run.started_at = timezone.now()
    if run.status in {"succeeded", "failed"} and run.finished_at is None:
        run.finished_at = timezone.now()
    run.save()
    if run.status in {"succeeded", "failed"}:
        _write_run_summary(run)
        _prune_run_artifacts()
    return JsonResponse({"status": run.status})


@csrf_exempt
def internal_run_artifact(request: HttpRequest, run_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    run = get_object_or_404(Run, id=run_id)
    if request.method == "GET":
        artifacts = [
            {"id": str(artifact.id), "name": artifact.name, "kind": artifact.kind, "url": artifact.url}
            for artifact in run.artifacts.all().order_by("created_at")
        ]
        return JsonResponse({"artifacts": artifacts})
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    name = payload.get("name")
    if not name:
        return JsonResponse({"error": "name required"}, status=400)
    artifact = RunArtifact.objects.create(
        run=run,
        name=name,
        kind=payload.get("kind", ""),
        url=payload.get("url", ""),
        metadata_json=payload.get("metadata_json"),
    )
    return JsonResponse({"id": str(artifact.id)})


@csrf_exempt
def internal_run_commands(request: HttpRequest, run_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    run = get_object_or_404(Run, id=run_id)
    if request.method == "GET":
        data = [
            {
                "id": str(cmd.id),
                "step_name": cmd.step_name,
                "command_index": cmd.command_index,
                "shell": cmd.shell,
                "status": cmd.status,
                "exit_code": cmd.exit_code,
                "started_at": cmd.started_at,
                "finished_at": cmd.finished_at,
                "ssm_command_id": cmd.ssm_command_id,
                "stdout": cmd.stdout,
                "stderr": cmd.stderr,
            }
            for cmd in run.command_executions.all()
        ]
        return JsonResponse({"commands": data})
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    started_at = parse_datetime(payload.get("started_at")) if payload.get("started_at") else None
    finished_at = parse_datetime(payload.get("finished_at")) if payload.get("finished_at") else None
    cmd = RunCommandExecution.objects.create(
        run=run,
        step_name=payload.get("step_name", ""),
        command_index=int(payload.get("command_index") or 0),
        shell=payload.get("shell", "sh"),
        status=payload.get("status", "pending"),
        exit_code=payload.get("exit_code"),
        started_at=started_at,
        finished_at=finished_at,
        ssm_command_id=payload.get("ssm_command_id", ""),
        stdout=payload.get("stdout", ""),
        stderr=payload.get("stderr", ""),
    )
    return JsonResponse({"id": str(cmd.id)})


@csrf_exempt
def internal_registry_sync(request: HttpRequest, registry_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    registry = get_object_or_404(Registry, id=registry_id)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    if status := payload.get("status"):
        registry.status = status
    registry.last_sync_at = timezone.now()
    registry.save(update_fields=["last_sync_at", "status", "updated_at"])
    return JsonResponse({"status": "synced", "last_sync_at": registry.last_sync_at})


@csrf_exempt
def internal_release_plan_generate(request: HttpRequest, plan_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    plan = get_object_or_404(ReleasePlan, id=plan_id)
    if not plan.milestones_json:
        plan.milestones_json = {"status": "placeholder", "notes": "Generation not implemented yet"}
        plan.save(update_fields=["milestones_json", "updated_at"])
    return JsonResponse({"status": "generated"})


def internal_registry_detail(request: HttpRequest, registry_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    registry = get_object_or_404(Registry, id=registry_id)
    return JsonResponse(
        {
            "id": str(registry.id),
            "name": registry.name,
            "registry_type": registry.registry_type,
            "description": registry.description,
            "url": registry.url,
            "status": registry.status,
            "last_sync_at": registry.last_sync_at,
        }
    )


def internal_release_plan_detail(request: HttpRequest, plan_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    plan = get_object_or_404(ReleasePlan, id=plan_id)
    return JsonResponse(
        {
            "id": str(plan.id),
            "name": plan.name,
            "target_kind": plan.target_kind,
            "target_fqn": plan.target_fqn,
            "from_version": plan.from_version,
            "to_version": plan.to_version,
            "milestones_json": plan.milestones_json,
            "blueprint_id": str(plan.blueprint_id) if plan.blueprint_id else None,
            "environment_id": str(plan.environment_id) if plan.environment_id else None,
            "last_run": str(plan.last_run_id) if plan.last_run_id else None,
        }
    )


@csrf_exempt
def internal_release_plan_upsert(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    blueprint_id = payload.get("blueprint_id")
    target_kind = payload.get("target_kind", "blueprint")
    target_fqn = payload.get("target_fqn", "")
    environment_id = payload.get("environment_id")
    if not environment_id:
        default_env = Environment.objects.filter(slug="local").first() or Environment.objects.first()
        if default_env:
            environment_id = str(default_env.id)
    if not environment_id:
        return JsonResponse({"error": "environment_id required"}, status=400)
    if target_fqn and target_fqn != "unknown":
        default_name = f"Release plan for {target_fqn}"
    else:
        default_name = "Release plan"
    name = payload.get("name") or default_name
    to_version = payload.get("to_version") or "0.1.0"
    from_version = payload.get("from_version") or ""
    milestones_json = payload.get("milestones_json")
    plan, _created = ReleasePlan.objects.get_or_create(
        blueprint_id=blueprint_id,
        target_kind=target_kind,
        target_fqn=target_fqn,
        defaults={
            "name": name,
            "from_version": from_version,
            "to_version": to_version,
            "milestones_json": milestones_json,
            "environment_id": environment_id,
        },
    )
    changed = False
    if name and plan.name != name:
        plan.name = name
        changed = True
    if to_version and plan.to_version != to_version:
        plan.to_version = to_version
        changed = True
    if from_version is not None and plan.from_version != from_version:
        plan.from_version = from_version
        changed = True
    if milestones_json is not None:
        plan.milestones_json = milestones_json
        changed = True
    if blueprint_id and plan.blueprint_id != blueprint_id:
        plan.blueprint_id = blueprint_id
        changed = True
    if environment_id and str(plan.environment_id) != str(environment_id):
        plan.environment_id = environment_id
        changed = True
    if payload.get("last_run_id"):
        plan.last_run_id = payload.get("last_run_id")
        changed = True
    if changed:
        plan.save()
    return JsonResponse({"id": str(plan.id)})


@csrf_exempt
def internal_release_plan_deploy_state(request: HttpRequest, plan_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method == "GET":
        instance_id = request.GET.get("instance_id")
        if not instance_id:
            return JsonResponse({"error": "instance_id required"}, status=400)
        state = ReleasePlanDeployment.objects.filter(
            release_plan_id=plan_id, instance_id=instance_id
        ).first()
        if not state:
            return JsonResponse({"state": None})
        return JsonResponse(
            {
                "state": {
                    "last_applied_hash": state.last_applied_hash,
                    "last_applied_at": state.last_applied_at,
                }
            }
        )
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    instance_id = payload.get("instance_id")
    if not instance_id:
        return JsonResponse({"error": "instance_id required"}, status=400)
    state, _ = ReleasePlanDeployment.objects.get_or_create(
        release_plan_id=plan_id, instance_id=instance_id
    )
    if payload.get("last_applied_hash") is not None:
        state.last_applied_hash = payload.get("last_applied_hash", "")
    if payload.get("last_applied_at"):
        state.last_applied_at = payload.get("last_applied_at")
    state.save()
    return JsonResponse({"status": "ok"})


def _deployment_response(deployment: Deployment, existing: bool) -> JsonResponse:
    return JsonResponse(
        {
            "deployment_id": str(deployment.id),
            "status": deployment.status,
            "existing": existing,
            "app_id": deployment.app_id,
            "environment_id": str(deployment.environment_id) if deployment.environment_id else None,
            "error_message": deployment.error_message,
            "health_check_status": deployment.health_check_status,
            "health_check_details_json": deployment.health_check_details_json or {},
            "rollback_of_deployment_id": str(deployment.rollback_of_id) if deployment.rollback_of_id else None,
            "stdout_excerpt": deployment.stdout_excerpt,
            "stderr_excerpt": deployment.stderr_excerpt,
            "started_at": deployment.started_at,
            "finished_at": deployment.finished_at,
            "artifacts_json": deployment.artifacts_json or {},
        }
    )


@csrf_exempt
def internal_deployments(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    release_id = payload.get("release_id")
    instance_id = payload.get("instance_id")
    if not release_id or not instance_id:
        return JsonResponse({"error": "release_id and instance_id required"}, status=400)
    release = get_object_or_404(Release, id=release_id)
    allow_draft = bool(payload.get("allow_draft"))
    allow_unready = bool(payload.get("allow_unready"))
    if release.status != "published" and not allow_draft:
        return JsonResponse({"error": "release must be published"}, status=400)
    if release.build_state != "ready" and not allow_unready:
        return JsonResponse({"error": "release build is not ready"}, status=400)
    instance = get_object_or_404(ProvisionedInstance, id=instance_id)
    release_plan = None
    if payload.get("release_plan_id"):
        release_plan = get_object_or_404(ReleasePlan, id=payload.get("release_plan_id"))
    elif release.release_plan_id:
        release_plan = ReleasePlan.objects.filter(id=release.release_plan_id).first()
    if release_plan:
        if not release_plan.environment_id:
            return JsonResponse({"error": "release_plan missing environment"}, status=400)
        if not instance.environment_id:
            return JsonResponse({"error": "instance missing environment"}, status=400)
        if str(release_plan.environment_id) != str(instance.environment_id):
            return JsonResponse({"error": "instance environment does not match release plan"}, status=400)
    deploy_kind = "release_plan" if release_plan else "release"
    base_key = compute_idempotency_base(release, instance, release_plan, deploy_kind)
    force = bool(payload.get("force"))
    existing = (
        Deployment.objects.filter(idempotency_base=base_key)
        .order_by("-created_at")
        .first()
    )
    if existing and existing.status in {"queued", "running"} and not force:
        try:
            stale_seconds = int(os.environ.get("XYENCE_DEPLOYMENT_STALE_SECONDS", "900") or "900")
        except ValueError:
            stale_seconds = 900
        anchor = existing.started_at or existing.created_at
        age_seconds = int((timezone.now() - anchor).total_seconds()) if anchor else 0
        if age_seconds > stale_seconds:
            existing.status = "failed"
            existing.error_message = f"stale deployment exceeded {stale_seconds}s"
            existing.finished_at = timezone.now()
            existing.save(update_fields=["status", "error_message", "finished_at", "updated_at"])
        else:
            return _deployment_response(existing, True)
    if existing and not force:
        return _deployment_response(existing, True)
    idempotency_key = base_key
    if force and existing:
        idempotency_key = hashlib.sha256(f"{base_key}:{uuid.uuid4()}".encode("utf-8")).hexdigest()
    deployment = Deployment.objects.create(
        idempotency_key=idempotency_key,
        idempotency_base=base_key,
        app_id=infer_app_id(release, release_plan),
        environment_id=release_plan.environment_id if release_plan else instance.environment_id,
        release=release,
        instance=instance,
        release_plan=release_plan,
        deploy_kind=deploy_kind,
        submitted_by=payload.get("submitted_by", "worker"),
        status="queued",
    )
    plan_json = load_release_plan_json(release, release_plan)
    if not plan_json:
        deployment.status = "failed"
        deployment.error_message = "release_plan.json not found for deployment"
        deployment.finished_at = timezone.now()
        deployment.save(update_fields=["status", "error_message", "finished_at", "updated_at"])
        return _deployment_response(deployment, False)
    if not instance.instance_id or not instance.aws_region:
        deployment.status = "failed"
        deployment.error_message = "instance missing instance_id or aws_region"
        deployment.finished_at = timezone.now()
        deployment.save(update_fields=["status", "error_message", "finished_at", "updated_at"])
        return _deployment_response(deployment, False)
    execute_release_plan_deploy(deployment, release, instance, release_plan, plan_json)
    rollback = maybe_trigger_rollback(deployment)
    if rollback:
        return JsonResponse(
            {
                "deployment_id": str(deployment.id),
                "status": deployment.status,
                "existing": False,
                "app_id": deployment.app_id,
                "environment_id": str(deployment.environment_id) if deployment.environment_id else None,
                "error_message": deployment.error_message,
                "health_check_status": deployment.health_check_status,
                "health_check_details_json": deployment.health_check_details_json or {},
                "rollback_deployment_id": str(rollback.id),
                "rollback_status": rollback.status,
                "stdout_excerpt": deployment.stdout_excerpt,
                "stderr_excerpt": deployment.stderr_excerpt,
                "started_at": deployment.started_at,
                "finished_at": deployment.finished_at,
                "artifacts_json": deployment.artifacts_json or {},
            }
        )
    return _deployment_response(deployment, False)


@csrf_exempt
def internal_deployment_detail(request: HttpRequest, deployment_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    deployment = get_object_or_404(Deployment, id=deployment_id)
    return JsonResponse(
        {
            "deployment_id": str(deployment.id),
            "status": deployment.status,
            "app_id": deployment.app_id,
            "environment_id": str(deployment.environment_id) if deployment.environment_id else None,
            "release_id": str(deployment.release_id),
            "instance_id": str(deployment.instance_id),
            "release_plan_id": str(deployment.release_plan_id) if deployment.release_plan_id else None,
            "deploy_kind": deployment.deploy_kind,
            "health_check_status": deployment.health_check_status,
            "health_check_details_json": deployment.health_check_details_json or {},
            "rollback_of_deployment_id": str(deployment.rollback_of_id) if deployment.rollback_of_id else None,
            "started_at": deployment.started_at,
            "finished_at": deployment.finished_at,
            "stdout_excerpt": deployment.stdout_excerpt,
            "stderr_excerpt": deployment.stderr_excerpt,
            "error_message": deployment.error_message,
            "transport_ref": deployment.transport_ref or {},
            "artifacts_json": deployment.artifacts_json or {},
        }
    )


@csrf_exempt
def internal_deployment_rollback(request: HttpRequest, deployment_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    deployment = get_object_or_404(Deployment, id=deployment_id)
    rollback = maybe_trigger_rollback(deployment)
    if not rollback:
        return JsonResponse({"error": "rollback unavailable"}, status=400)
    return JsonResponse(
        {
            "deployment_id": str(deployment.id),
            "rollback_deployment_id": str(rollback.id),
            "rollback_status": rollback.status,
        }
    )


@csrf_exempt
def internal_release_target_deploy_manifest(request: HttpRequest, target_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    active = Run.objects.filter(
        status__in=["pending", "running"],
        metadata_json__release_target_id=str(target_id),
    ).order_by("-created_at").first()
    if active:
        return JsonResponse({"error": "deploy_in_progress", "active_run_id": str(active.id)}, status=409)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    manifest_run_id = payload.get("manifest_run_id")
    manifest_artifact = payload.get("manifest_artifact") or "release_manifest.json"
    compose_artifact = payload.get("compose_artifact") or "compose.release.yml"
    if not manifest_run_id:
        return JsonResponse({"error": "manifest_run_id required"}, status=400)
    release_target = get_object_or_404(ReleaseTarget, id=target_id)
    blueprint = release_target.blueprint
    if not blueprint:
        return JsonResponse({"error": "release target missing blueprint"}, status=400)
    source_manifest = RunArtifact.objects.filter(run_id=manifest_run_id, name=manifest_artifact).first()
    source_compose = RunArtifact.objects.filter(run_id=manifest_run_id, name=compose_artifact).first()
    if not source_manifest or not source_compose:
        return JsonResponse({"error": "manifest or compose artifact not found"}, status=404)
    run = Run.objects.create(
        entity_type="blueprint",
        entity_id=blueprint.id,
        status="running",
        summary=f"Deploy manifest for {blueprint.namespace}.{blueprint.name}",
        log_text="Preparing deploy-by-manifest run\n",
        metadata_json={"release_target_id": str(release_target.id)},
    )
    RunArtifact.objects.create(
        run=run,
        name=manifest_artifact,
        kind=source_manifest.kind or "release_manifest",
        url=source_manifest.url,
    )
    RunArtifact.objects.create(
        run=run,
        name=compose_artifact,
        kind=source_compose.kind or "compose",
        url=source_compose.url,
    )
    module_catalog = _build_module_catalog()
    _write_run_artifact(run, "module_catalog.v1.json", module_catalog, "module_catalog")
    release_payload = _release_target_payload(release_target)
    _write_run_artifact(run, "release_target.json", release_payload, "release_target")
    run_history_summary = _build_run_history_summary(blueprint)
    _write_run_artifact(run, "run_history_summary.v1.json", run_history_summary, "run_history_summary")
    implementation_plan = _generate_implementation_plan(
        blueprint,
        module_catalog=module_catalog,
        run_history_summary=run_history_summary,
        release_target=release_payload,
        manifest_override=True,
    )
    _write_run_artifact(run, "implementation_plan.json", implementation_plan, "implementation_plan")
    _queue_dev_tasks_for_plan(
        blueprint=blueprint,
        run=run,
        plan=implementation_plan,
        namespace=blueprint.namespace,
        project_key=f"{blueprint.namespace}.{blueprint.name}",
        release_target=release_payload,
        enqueue_jobs=True,
    )
    run.status = "succeeded"
    run.finished_at = timezone.now()
    run.log_text = (run.log_text or "") + "Queued deploy-by-manifest tasks\n"
    run.save(update_fields=["status", "finished_at", "log_text", "updated_at"])
    _write_run_summary(run)
    return JsonResponse({"run_id": str(run.id), "status": run.status})


@csrf_exempt
def internal_release_target_deploy_release(request: HttpRequest, target_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    active = Run.objects.filter(
        status__in=["pending", "running"],
        metadata_json__release_target_id=str(target_id),
    ).order_by("-created_at").first()
    if active:
        return JsonResponse({"error": "deploy_in_progress", "active_run_id": str(active.id)}, status=409)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    release_uuid = payload.get("release_uuid")
    release_version = payload.get("release_version")
    if not release_uuid and not release_version:
        return JsonResponse({"error": "release_uuid or release_version required"}, status=400)
    release_target = get_object_or_404(ReleaseTarget, id=target_id)
    blueprint = release_target.blueprint
    if not blueprint:
        return JsonResponse({"error": "release target missing blueprint"}, status=400)
    if release_uuid:
        release = Release.objects.filter(id=release_uuid).first()
    else:
        release = Release.objects.filter(version=release_version, blueprint_id=blueprint.id).first()
    if not release:
        return JsonResponse({"error": "release not found"}, status=404)
    allow_unready = bool(payload.get("allow_unready"))
    if release.status != "published":
        return JsonResponse({"error": "release must be published"}, status=400)
    if release.build_state != "ready" and not allow_unready:
        return JsonResponse({"error": "release build is not ready"}, status=400)
    artifacts_json = release.artifacts_json or {}
    manifest_info = artifacts_json.get("release_manifest") or {}
    compose_info = artifacts_json.get("compose_file") or {}
    if not manifest_info.get("url") or not compose_info.get("url"):
        return JsonResponse({"error": "release artifacts missing"}, status=400)
    run = Run.objects.create(
        entity_type="blueprint",
        entity_id=blueprint.id,
        status="running",
        summary=f"Deploy release {release.version} for {blueprint.namespace}.{blueprint.name}",
        log_text="Preparing deploy-by-release run\n",
        metadata_json={
            "release_target_id": str(release_target.id),
            "release_uuid": str(release.id),
            "release_version": release.version,
        },
    )
    RunArtifact.objects.create(
        run=run,
        name="release_manifest.json",
        kind="release_manifest",
        url=manifest_info.get("url"),
    )
    RunArtifact.objects.create(
        run=run,
        name="compose.release.yml",
        kind="compose",
        url=compose_info.get("url"),
    )
    module_catalog = _build_module_catalog()
    _write_run_artifact(run, "module_catalog.v1.json", module_catalog, "module_catalog")
    release_payload = _release_target_payload(release_target)
    _write_run_artifact(run, "release_target.json", release_payload, "release_target")
    run_history_summary = _build_run_history_summary(blueprint)
    _write_run_artifact(run, "run_history_summary.v1.json", run_history_summary, "run_history_summary")
    implementation_plan = _generate_implementation_plan(
        blueprint,
        module_catalog=module_catalog,
        run_history_summary=run_history_summary,
        release_target=release_payload,
        manifest_override=True,
    )
    for item in implementation_plan.get("work_items", []):
        if item.get("id") == "deploy.apply_remote_compose.pull":
            item.setdefault("config", {})
            item["config"]["release_uuid"] = str(release.id)
            item["config"]["release_version"] = release.version
    _write_run_artifact(run, "implementation_plan.json", implementation_plan, "implementation_plan")
    _queue_dev_tasks_for_plan(
        blueprint=blueprint,
        run=run,
        plan=implementation_plan,
        namespace=blueprint.namespace,
        project_key=f"{blueprint.namespace}.{blueprint.name}",
        release_target=release_payload,
        enqueue_jobs=True,
    )
    run.status = "succeeded"
    run.finished_at = timezone.now()
    run.log_text = (run.log_text or "") + "Queued deploy-by-release tasks\n"
    run.save(update_fields=["status", "finished_at", "log_text", "metadata_json", "updated_at"])
    _write_run_summary(run)
    return JsonResponse({"run_id": str(run.id), "status": run.status})


@csrf_exempt
def internal_release_target_current_release(request: HttpRequest, target_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    state = get_release_target_deploy_state(target_id)
    if not state:
        return JsonResponse({"current_release": None})
    return JsonResponse(
        {
            "release_uuid": state.get("release_uuid"),
            "release_version": state.get("release_version"),
            "deployed_at": state.get("deployed_at"),
            "outcome": state.get("deploy_outcome"),
            "run_id": state.get("run_id"),
            "manifest_sha": (state.get("manifest") or {}).get("content_hash"),
            "compose_sha": (state.get("compose") or {}).get("content_hash"),
        }
    )


@csrf_exempt
def internal_release_target_check_drift(request: HttpRequest, target_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    release_target = get_object_or_404(ReleaseTarget, id=target_id)
    blueprint = release_target.blueprint
    instance = ProvisionedInstance.objects.filter(id=release_target.target_instance_id).first()
    if not instance or not instance.instance_id:
        return JsonResponse({"error": "target instance missing"}, status=400)
    state = get_release_target_deploy_state(target_id)
    expected = {
        "release_uuid": state.get("release_uuid") if state else "",
        "manifest_sha256": (state.get("manifest") or {}).get("content_hash") if state else "",
        "compose_sha256": (state.get("compose") or {}).get("content_hash") if state else "",
    }
    runtime = (release_target.config_json or {}).get("runtime") if hasattr(release_target, "config_json") else {}
    if (runtime or {}).get("remote_root"):
        remote_root = str((runtime or {}).get("remote_root"))
    else:
        project_key = f"{blueprint.namespace}.{blueprint.name}" if blueprint else ""
        remote_root_slug = re.sub(r"[^a-z0-9]+", "-", project_key.lower()).strip("-") or "default"
        remote_root = f"/opt/xyn/apps/{remote_root_slug}"
    actual = _ssm_fetch_runtime_marker(instance.instance_id, instance.aws_region or "", remote_root)
    drift = False
    if expected.get("release_uuid") and expected.get("release_uuid") != actual.get("release_uuid"):
        drift = True
    if expected.get("manifest_sha256") and expected.get("manifest_sha256") != actual.get("manifest_sha256"):
        drift = True
    if expected.get("compose_sha256") and expected.get("compose_sha256") != actual.get("compose_sha256"):
        drift = True
    return JsonResponse({"drift": drift, "expected": expected, "actual": actual})


@csrf_exempt
def internal_releases_latest(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    blueprint_id = request.GET.get("blueprint_id")
    if not blueprint_id:
        return JsonResponse({"error": "blueprint_id required"}, status=400)
    qs = Release.objects.filter(blueprint_id=blueprint_id, status="published")
    release = qs.order_by("-created_at").first()
    if not release:
        return JsonResponse({"error": "release not found"}, status=404)
    return JsonResponse({"id": str(release.id), "version": release.version})


@csrf_exempt
def internal_release_target_deploy_latest(request: HttpRequest, target_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    active = Run.objects.filter(
        status__in=["pending", "running"],
        metadata_json__release_target_id=str(target_id),
    ).order_by("-created_at").first()
    if active:
        return JsonResponse({"error": "deploy_in_progress", "active_run_id": str(active.id)}, status=409)
    release_target = get_object_or_404(ReleaseTarget, id=target_id)
    blueprint = release_target.blueprint
    if not blueprint:
        return JsonResponse({"error": "release target missing blueprint"}, status=400)
    release = Release.objects.filter(blueprint_id=blueprint.id, status="published").order_by("-created_at").first()
    if not release:
        return JsonResponse({"error": "release not found"}, status=404)
    request_payload = json.dumps({"release_uuid": str(release.id)})
    deploy_request = HttpRequest()
    deploy_request.method = "POST"
    deploy_request._body = request_payload.encode("utf-8")
    deploy_request.headers = request.headers
    return internal_release_target_deploy_release(deploy_request, target_id)


@csrf_exempt
def internal_release_target_rollback_last_success(request: HttpRequest, target_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    active = Run.objects.filter(
        status__in=["pending", "running"],
        metadata_json__release_target_id=str(target_id),
    ).order_by("-created_at").first()
    if active:
        return JsonResponse({"error": "deploy_in_progress", "active_run_id": str(active.id)}, status=409)
    state = get_release_target_deploy_state(target_id)
    current_uuid = (state or {}).get("release_uuid")
    if not current_uuid:
        return JsonResponse({"error": "no_current_release"}, status=404)
    prior = (
        Run.objects.filter(
            metadata_json__release_target_id=str(target_id),
            metadata_json__deploy_outcome__in=["succeeded", "noop"],
        )
        .exclude(metadata_json__release_uuid=current_uuid)
        .order_by("-created_at")
        .first()
    )
    if not prior or not prior.metadata_json:
        return JsonResponse({"error": "no_prior_successful_release"}, status=404)
    release_uuid = prior.metadata_json.get("release_uuid")
    if not release_uuid:
        return JsonResponse({"error": "no_prior_successful_release"}, status=404)
    request_payload = json.dumps({"release_uuid": release_uuid})
    deploy_request = HttpRequest()
    deploy_request.method = "POST"
    deploy_request._body = request_payload.encode("utf-8")
    deploy_request.headers = request.headers
    return internal_release_target_deploy_release(deploy_request, target_id)


def _build_release_retention(
    blueprint_id: str, environment_id: Optional[str], keep: int
) -> Dict[str, Any]:
    qs = Release.objects.filter(blueprint_id=blueprint_id, status="published").order_by("-created_at")
    releases = list(qs)
    retained = releases[:keep]
    candidates = releases[keep:]
    targets_qs = ReleaseTarget.objects.filter(blueprint_id=blueprint_id)
    referenced_ids = set()
    for target in targets_qs:
        state = get_release_target_deploy_state(str(target.id))
        rel_uuid = (state or {}).get("release_uuid")
        if rel_uuid:
            referenced_ids.add(rel_uuid)
    protected = [rel for rel in releases if str(rel.id) in referenced_ids and rel not in retained]
    return {
        "retained": retained,
        "candidates": candidates,
        "protected": protected,
        "totals": {
            "retained": len(retained),
            "candidates": len(candidates),
            "protected": len(protected),
            "total": len(releases),
        },
    }


def _write_gc_result(payload: Dict[str, Any]) -> str:
    gc_dir = os.path.join(settings.MEDIA_ROOT, "gc_results")
    os.makedirs(gc_dir, exist_ok=True)
    filename = f"{uuid.uuid4()}.json"
    file_path = os.path.join(gc_dir, filename)
    with open(file_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return f"{settings.MEDIA_URL.rstrip('/')}/gc_results/{filename}"


@csrf_exempt
def internal_releases_retention_report(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    blueprint_id = request.GET.get("blueprint_id")
    environment_id = request.GET.get("environment_id")
    keep = int(request.GET.get("keep", 20))
    if not blueprint_id:
        return JsonResponse({"error": "blueprint_id required"}, status=400)
    plan = _build_release_retention(blueprint_id, environment_id, keep)
    retained = plan["retained"]
    candidates = plan["candidates"]
    protected = plan["protected"]
    return JsonResponse(
        {
            "retained": [
                {"id": str(rel.id), "version": rel.version, "created_at": rel.created_at.isoformat()}
                for rel in retained
            ],
            "candidates": [
                {"id": str(rel.id), "version": rel.version, "created_at": rel.created_at.isoformat()}
                for rel in candidates
            ],
            "protected": [
                {"id": str(rel.id), "version": rel.version, "created_at": rel.created_at.isoformat()}
                for rel in protected
            ],
            "totals": {
                **plan["totals"],
            },
        }
    )


@csrf_exempt
def internal_artifacts_orphans_report(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    older_than_days = int(request.GET.get("older_than_days") or 30)
    cutoff = timezone.now() - timezone.timedelta(days=older_than_days)
    referenced_urls = set()
    for rel in Release.objects.exclude(artifacts_json__isnull=True):
        artifacts = rel.artifacts_json or {}
        for key in ("release_manifest", "compose_file", "build_result"):
            entry = artifacts.get(key) or {}
            url = entry.get("url")
            if url:
                referenced_urls.add(url)
    orphans = RunArtifact.objects.filter(created_at__lt=cutoff).exclude(url__in=referenced_urls)
    sample = [
        {"id": str(artifact.id), "name": artifact.name, "url": artifact.url}
        for artifact in orphans[:50]
    ]
    return JsonResponse(
        {
            "older_than_days": older_than_days,
            "orphans_count": orphans.count(),
            "sample": sample,
        }
    )


@csrf_exempt
def internal_releases_gc(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    blueprint_id = payload.get("blueprint_id")
    environment_id = payload.get("environment_id")
    keep = int(payload.get("keep", 20))
    dry_run = bool(payload.get("dry_run", True))
    confirm = bool(payload.get("confirm", False))
    if not blueprint_id:
        return JsonResponse({"error": "blueprint_id required"}, status=400)
    plan = _build_release_retention(blueprint_id, environment_id, keep)
    candidates = plan["candidates"]
    if dry_run:
        result = {
            "dry_run": True,
            "deprecated_count": 0,
            "candidates": [str(rel.id) for rel in candidates],
        }
        url = _write_gc_result(result)
        return JsonResponse({**result, "gc_result_url": url})
    if not confirm:
        return JsonResponse({"error": "confirm required"}, status=400)
    updated = Release.objects.filter(id__in=[rel.id for rel in candidates]).update(status="deprecated")
    result = {
        "dry_run": False,
        "deprecated_count": updated,
        "candidates": [str(rel.id) for rel in candidates],
    }
    url = _write_gc_result(result)
    return JsonResponse({**result, "gc_result_url": url})


@csrf_exempt
def internal_artifacts_gc(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    blueprint_id = payload.get("blueprint_id")
    environment_id = payload.get("environment_id")
    keep = int(payload.get("keep", 20))
    dry_run = bool(payload.get("dry_run", True))
    confirm = bool(payload.get("confirm", False))
    older_than_days = int(payload.get("older_than_days") or 30)
    if not blueprint_id:
        return JsonResponse({"error": "blueprint_id required"}, status=400)
    plan = _build_release_retention(blueprint_id, environment_id, keep)
    keep_ids = {rel.id for rel in plan["retained"] + plan["protected"]}
    referenced_urls = set()
    for rel in Release.objects.filter(id__in=keep_ids):
        artifacts = rel.artifacts_json or {}
        for key in ("release_manifest", "compose_file", "build_result"):
            entry = artifacts.get(key) or {}
            url = entry.get("url")
            if url:
                referenced_urls.add(url)
    cutoff = timezone.now() - timezone.timedelta(days=older_than_days)
    orphans = RunArtifact.objects.filter(created_at__lt=cutoff).exclude(url__in=referenced_urls)
    if dry_run:
        result = {
            "dry_run": True,
            "deleted_count": 0,
            "orphans_count": orphans.count(),
        }
        url = _write_gc_result(result)
        return JsonResponse({**result, "gc_result_url": url})
    if not confirm:
        return JsonResponse({"error": "confirm required"}, status=400)
    deleted_count, _ = orphans.delete()
    result = {
        "dry_run": False,
        "deleted_count": deleted_count,
        "orphans_count": 0,
    }
    url = _write_gc_result(result)
    return JsonResponse({**result, "gc_result_url": url})


@csrf_exempt
def internal_ecr_gc_report(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    blueprint_id = request.GET.get("blueprint_id")
    environment_id = request.GET.get("environment_id")
    keep = int(request.GET.get("keep") or 20)
    if not blueprint_id:
        return JsonResponse({"error": "blueprint_id required"}, status=400)
    report = internal_releases_retention_report(request)
    if report.status_code != 200:
        return report
    payload = json.loads(report.content.decode("utf-8"))
    retained_ids = {entry["id"] for entry in payload.get("retained", [])}
    protected_ids = {entry["id"] for entry in payload.get("protected", [])}
    keep_ids = retained_ids | protected_ids
    releases = Release.objects.filter(id__in=keep_ids)
    referenced_digests = set()
    for rel in releases:
        artifacts = rel.artifacts_json or {}
        manifest_info = artifacts.get("release_manifest") or {}
        url = manifest_info.get("url")
        if not url:
            continue
        try:
            manifest = requests.get(url, timeout=30).json()
        except Exception:
            continue
        images = manifest.get("images") or {}
        for meta in images.values():
            digest = (meta or {}).get("digest")
            if digest:
                referenced_digests.add(digest)
    return JsonResponse(
        {
            "blueprint_id": blueprint_id,
            "environment_id": environment_id,
            "keep": keep,
            "referenced_digests": sorted(referenced_digests),
            "note": "ECR GC report is digest-only; no deletions performed.",
        }
    )


@csrf_exempt
def internal_release_promote(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    release_uuid = payload.get("release_uuid")
    allow_existing = bool(payload.get("allow_existing"))
    if not release_uuid:
        return JsonResponse({"error": "release_uuid required"}, status=400)
    source = Release.objects.filter(id=release_uuid).first()
    if not source:
        return JsonResponse({"error": "source release not found"}, status=404)
    if source.status == "draft":
        return JsonResponse({"error": "cannot promote draft release"}, status=400)
    existing = (
        Release.objects.filter(blueprint_id=source.blueprint_id, version=source.version)
        .exclude(id=source.id)
        .first()
    )
    if existing:
        if allow_existing:
            return JsonResponse({"id": str(existing.id), "version": existing.version})
        return JsonResponse({"error": "release already exists"}, status=409)
    return JsonResponse({"id": str(source.id), "version": source.version})


@csrf_exempt
def internal_release_create(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    blueprint_id = payload.get("blueprint_id")
    release_plan_id = payload.get("release_plan_id")
    created_from_run_id = payload.get("created_from_run_id")
    version = payload.get("version")
    if not version:
        version = _next_release_version_for_blueprint(str(blueprint_id or ""))
    status = payload.get("status", "draft")
    build_state = payload.get("build_state")
    if not build_state:
        build_state = "building" if status == "published" else "draft"
    release = Release.objects.create(
        blueprint_id=blueprint_id,
        release_plan_id=release_plan_id,
        created_from_run_id=created_from_run_id,
        version=version,
        status=status,
        build_state=build_state,
        artifacts_json=payload.get("artifacts_json"),
    )
    return JsonResponse({"id": str(release.id), "version": release.version})


@csrf_exempt
def internal_release_upsert(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    release_uuid = payload.get("release_uuid")
    blueprint_id = payload.get("blueprint_id")
    version = payload.get("version")
    release = None
    if release_uuid:
        release = Release.objects.filter(id=release_uuid).first()
        if not release:
            return JsonResponse({"error": "release not found"}, status=404)
        blueprint_id = release.blueprint_id
        version = release.version
    if not blueprint_id or not version:
        return JsonResponse({"error": "blueprint_id and version required"}, status=400)
    if not release:
        release = Release.objects.filter(blueprint_id=blueprint_id, version=version).first()
    if release:
        allow_overwrite = bool(payload.get("allow_overwrite"))
        if release.status == "published" and not allow_overwrite:
            incoming = payload.get("artifacts_json") or {}
            existing = release.artifacts_json or {}
            def _hash(obj: Dict[str, Any]) -> str:
                return str((obj or {}).get("sha256") or "")
            incoming_manifest = _hash(incoming.get("release_manifest"))
            existing_manifest = _hash(existing.get("release_manifest"))
            if incoming_manifest and existing_manifest and incoming_manifest != existing_manifest:
                return JsonResponse({"error": "release is immutable"}, status=409)
            incoming_compose = _hash(incoming.get("compose_file"))
            existing_compose = _hash(existing.get("compose_file"))
            if incoming_compose and existing_compose and incoming_compose != existing_compose:
                return JsonResponse({"error": "release is immutable"}, status=409)
        release.status = payload.get("status", release.status)
        if payload.get("build_state"):
            release.build_state = payload.get("build_state")
        release.artifacts_json = payload.get("artifacts_json") or release.artifacts_json
        if payload.get("release_plan_id"):
            release.release_plan_id = payload.get("release_plan_id")
        if payload.get("created_from_run_id"):
            release.created_from_run_id = payload.get("created_from_run_id")
        release.save()
    else:
        status = payload.get("status", "draft")
        build_state = payload.get("build_state")
        if not build_state:
            build_state = "building" if status == "published" else "draft"
        release = Release.objects.create(
            blueprint_id=blueprint_id,
            release_plan_id=payload.get("release_plan_id"),
            created_from_run_id=payload.get("created_from_run_id"),
            version=version,
            status=status,
            build_state=build_state,
            artifacts_json=payload.get("artifacts_json"),
        )
    return JsonResponse({"id": str(release.id), "version": release.version})


@csrf_exempt
def internal_release_resolve(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    release_uuid = payload.get("release_uuid")
    release_version = payload.get("release_version")
    blueprint_id = payload.get("blueprint_id")
    release = None
    if release_uuid:
        release = Release.objects.filter(id=release_uuid).first()
    if not release and release_version:
        qs = Release.objects.filter(version=release_version)
        if blueprint_id:
            qs = qs.filter(blueprint_id=blueprint_id)
        release = qs.first()
    if not release:
        return JsonResponse({"error": "release not found"}, status=404)
    return JsonResponse(
        {
            "id": str(release.id),
            "version": release.version,
            "blueprint_id": str(release.blueprint_id) if release.blueprint_id else "",
            "artifacts_json": release.artifacts_json or {},
        }
    )


@csrf_exempt
def internal_instance_detail(request: HttpRequest, instance_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    instance = get_object_or_404(ProvisionedInstance, id=instance_id)
    return JsonResponse(
        {
            "id": str(instance.id),
            "desired_release_id": str(instance.desired_release_id)
            if instance.desired_release_id
            else None,
            "observed_release_id": str(instance.observed_release_id)
            if instance.observed_release_id
            else None,
            "health_status": instance.health_status,
        }
    )


@csrf_exempt
def internal_instance_state(request: HttpRequest, instance_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    instance = get_object_or_404(ProvisionedInstance, id=instance_id)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    if payload.get("desired_release_id") is not None:
        instance.desired_release_id = payload.get("desired_release_id")
    if payload.get("observed_release_id") is not None:
        instance.observed_release_id = payload.get("observed_release_id")
    if payload.get("observed_at") is not None:
        instance.observed_at = parse_datetime(payload.get("observed_at"))
    if payload.get("last_deploy_run_id") is not None:
        instance.last_deploy_run_id = payload.get("last_deploy_run_id")
    if payload.get("health_status") is not None:
        instance.health_status = payload.get("health_status")
    instance.save(
        update_fields=[
            "desired_release",
            "observed_release",
            "observed_at",
            "last_deploy_run",
            "health_status",
            "updated_at",
        ]
    )
    return JsonResponse({"status": "ok"})


@csrf_exempt
def internal_context_resolve(request: HttpRequest) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    purpose = payload.get("purpose", "any")
    namespace = payload.get("namespace")
    project_key = payload.get("project_key")
    selected_ids = payload.get("selected_ids")
    if selected_ids is not None and not isinstance(selected_ids, list):
        return JsonResponse({"error": "selected_ids must be a list"}, status=400)
    resolved = _resolve_context_packs(
        session=None,
        selected_ids=selected_ids,
        purpose=purpose,
        namespace=namespace,
        project_key=project_key,
        action=payload.get("action"),
    )
    return JsonResponse(
        {
            "effective_context": resolved.get("effective_context", ""),
            "context_pack_refs": resolved.get("refs", []),
            "context_hash": resolved.get("hash", ""),
        }
    )


@csrf_exempt
def internal_dev_task_detail(request: HttpRequest, task_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    task = get_object_or_404(DevTask, id=task_id)
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    resolved = _resolve_context_pack_list(list(task.context_packs.all()))
    return JsonResponse(
        {
            "id": str(task.id),
            "title": task.title,
            "task_type": task.task_type,
            "status": task.status,
            "work_item_id": task.work_item_id,
            "result_run": str(task.result_run_id) if task.result_run_id else None,
            "source_run": str(task.source_run_id) if task.source_run_id else None,
            "input_artifact_key": task.input_artifact_key,
            "target_instance_id": str(task.target_instance_id) if task.target_instance_id else None,
            "force": task.force,
            "context_pack_refs": resolved.get("refs", []),
            "context_hash": resolved.get("hash", ""),
            "context": resolved.get("effective_context", ""),
        }
    )


@csrf_exempt
def internal_dev_task_claim(request: HttpRequest, task_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    task = get_object_or_404(DevTask, id=task_id)
    if task.status not in {"queued", "running"}:
        return JsonResponse({"error": "Task not runnable"}, status=409)
    if task.task_type == "deploy_release_plan" and not task.target_instance_id:
        return JsonResponse({"error": "target_instance_id required for deploy_release_plan"}, status=400)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    worker_id = payload.get("worker_id", "worker")
    task.status = "running"
    task.locked_by = worker_id
    task.locked_at = timezone.now()
    task.attempts += 1
    task.save(update_fields=["status", "locked_by", "locked_at", "attempts", "updated_at"])
    if not task.result_run_id:
        run = Run.objects.create(
            entity_type="dev_task",
            entity_id=task.id,
            status="running",
            summary=f"Run dev task {task.title}",
            created_by=task.created_by,
            started_at=timezone.now(),
        )
        task.result_run = run
        task.save(update_fields=["result_run", "updated_at"])
    resolved = _resolve_context_pack_list(list(task.context_packs.all()))
    target_instance = task.target_instance
    return JsonResponse(
        {
            "id": str(task.id),
            "task_type": task.task_type,
            "status": task.status,
            "work_item_id": task.work_item_id,
            "result_run": str(task.result_run_id) if task.result_run_id else None,
            "source_run": str(task.source_run_id) if task.source_run_id else None,
            "source_entity_type": task.source_entity_type,
            "source_entity_id": str(task.source_entity_id),
            "input_artifact_key": task.input_artifact_key,
            "target_instance": {
                "id": str(target_instance.id),
                "instance_id": target_instance.instance_id,
                "aws_region": target_instance.aws_region,
                "name": target_instance.name,
            }
            if target_instance
            else None,
            "force": task.force,
            "context_pack_refs": resolved.get("refs", []),
            "context_hash": resolved.get("hash", ""),
            "context": resolved.get("effective_context", ""),
        }
    )


@csrf_exempt
def internal_dev_task_complete(request: HttpRequest, task_id: str) -> JsonResponse:
    if token_error := _require_internal_token(request):
        return token_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    task = get_object_or_404(DevTask, id=task_id)
    payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    status = payload.get("status")
    if status:
        task.status = status
    if error := payload.get("error"):
        task.last_error = error
    task.locked_by = ""
    task.locked_at = None
    task.save(update_fields=["status", "last_error", "locked_by", "locked_at", "updated_at"])
    return JsonResponse({"status": task.status})
