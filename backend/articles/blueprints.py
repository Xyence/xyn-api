import hashlib
import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Callable
from pathlib import Path
from typing import Any, Dict, List, Optional

from django.db import models
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
from jsonschema import Draft202012Validator

from .services import (
    generate_blueprint_draft,
    revise_blueprint_draft,
    transcribe_voice_note,
)
from .models import (
    Blueprint,
    BlueprintDraftSession,
    BlueprintInstance,
    BlueprintRevision,
    Bundle,
    Capability,
    ContextPack,
    DevTask,
    DraftSessionVoiceNote,
    Module,
    Registry,
    Release,
    ReleasePlan,
    ReleasePlanDeployState,
    ReleasePlanDeployment,
    Run,
    RunCommandExecution,
    RunArtifact,
    VoiceNote,
    VoiceTranscript,
)

_executor = ThreadPoolExecutor(max_workers=2)


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


def _validate_blueprint_spec(spec: Dict[str, Any], kind: str = "solution") -> List[str]:
    schema = _load_schema(_schema_for_kind(kind))
    validator = Draft202012Validator(schema)
    errors = []
    for error in sorted(validator.iter_errors(spec), key=lambda e: e.path):
        path = ".".join(str(p) for p in error.path) if error.path else "root"
        errors.append(f"{path}: {error.message}")
    return errors


def _load_runner_release_spec() -> Optional[Dict[str, Any]]:
    root = _contracts_root()
    if not root:
        return None
    fixture = root / "fixtures" / "runner.release.json"
    if not fixture.exists():
        return None
    return json.loads(fixture.read_text())


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
) -> List[DevTask]:
    tasks = []
    for item in plan.get("tasks", []):
        task_type = item.get("task_type") or "codegen"
        title = item.get("title") or f"{task_type} for {plan.get('blueprint')}"
        context_purpose = item.get("context_purpose") or "coder"
        dev_task = DevTask.objects.create(
            title=title,
            task_type=task_type,
            status="queued",
            priority=item.get("priority", 0),
            source_entity_type="blueprint",
            source_entity_id=plan.get("blueprint_id") or blueprint.id,
            source_run=run,
            input_artifact_key="implementation_plan.json",
            context_purpose=context_purpose,
            created_by=run.created_by,
            updated_by=run.created_by,
        )
        packs = _select_context_packs_for_dev_task(context_purpose, namespace, None, task_type)
        if packs:
            dev_task.context_packs.add(*packs)
        tasks.append(dev_task)
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
    session.save(update_fields=[
        "current_draft_json",
        "requirements_summary",
        "validation_errors_json",
        "suggested_fixes_json",
        "status",
        "updated_at",
    ])


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
        session.save(
            update_fields=[
                "context_pack_refs_json",
                "effective_context_hash",
                "effective_context_preview",
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
        return JsonResponse({"error": "Blueprint missing releaseSpec"}, status=400)
    payload = {}
    if request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError:
            payload = {}
    if not payload:
        payload = request.POST
    mode = payload.get("mode", "apply")
    queue_dev_tasks = request.GET.get("queue_dev_tasks") == "1"
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
        project_key=None,
    )
    run.context_pack_refs_json = context_resolved.get("refs", [])
    run.context_hash = context_resolved.get("hash", "")
    _build_context_artifacts(run, context_resolved)
    try:
        run.log_text = "Starting blueprint instantiate\n"
        plan = _xynseed_request("post", "/releases/plan", {"release_spec": release_spec})
        _write_run_artifact(run, "plan.json", plan, "plan")
        run.log_text += "Release plan created\n"
        op = None
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
        run.status = "succeeded" if instance.status in {"planned", "applied"} else "failed"
        run.metadata_json = {"plan": plan, "operation": op}
        implementation_plan = {
            "blueprint_id": str(blueprint.id),
            "blueprint": f"{blueprint.namespace}.{blueprint.name}",
            "generated_at": timezone.now().isoformat(),
            "tasks": [
                {
                    "task_type": "codegen",
                    "title": f"Codegen for {blueprint.namespace}.{blueprint.name}",
                    "context_purpose": "coder",
                }
                ,
                {
                    "task_type": "release_plan_generate",
                    "title": f"Release plan for {blueprint.namespace}.{blueprint.name}",
                    "context_purpose": "planner",
                }
            ],
        }
        _write_run_artifact(run, "implementation_plan.json", implementation_plan, "implementation_plan")
        plan_md = (
            f"# Implementation Plan\n\n"
            f"- Blueprint: {blueprint.namespace}.{blueprint.name}\n"
            f"- Generated: {implementation_plan['generated_at']}\n\n"
            "## Tasks\n"
        )
        for task in implementation_plan["tasks"]:
            plan_md += f"- {task['task_type']}: {task['title']}\n"
        _write_run_artifact(run, "implementation_plan.md", plan_md, "implementation_plan")
        run.log_text += "Implementation plan generated\n"
        if queue_dev_tasks:
            dev_tasks = _queue_dev_tasks_for_plan(
                blueprint=blueprint,
                run=run,
                plan=implementation_plan,
                namespace=blueprint.namespace,
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
        session.save(
            update_fields=[
                "context_pack_refs_json",
                "effective_context_hash",
                "effective_context_preview",
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
            draft = session.current_draft_json
            if not draft:
                messages.error(request, "No draft to publish.")
            else:
                errors = _validate_blueprint_spec(draft, session.blueprint_kind)
                if errors:
                    messages.error(request, "Draft has validation errors; fix before publishing.")
                else:
                    kind = session.blueprint_kind
                    if kind == "solution":
                        blueprint, created = Blueprint.objects.get_or_create(
                            name=draft["metadata"]["name"],
                            namespace=draft["metadata"].get("namespace", "core"),
                            defaults={
                                "description": draft.get("description", ""),
                                "created_by": request.user,
                                "updated_by": request.user,
                            },
                        )
                        if not created:
                            blueprint.description = draft.get("description", blueprint.description)
                            blueprint.updated_by = request.user
                            blueprint.save(update_fields=["description", "updated_by", "updated_at"])
                        next_rev = (blueprint.revisions.aggregate(max_rev=models.Max("revision")).get("max_rev") or 0) + 1
                        BlueprintRevision.objects.create(
                            blueprint=blueprint,
                            revision=next_rev,
                            spec_json=draft,
                            blueprint_kind=kind,
                            created_by=request.user,
                        )
                        session.linked_blueprint = blueprint
                        session.status = "published"
                        session.save(update_fields=["linked_blueprint", "status", "updated_at"])
                        messages.success(request, "Blueprint published.")
                        return redirect("blueprint-detail", blueprint_id=blueprint.id)
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
                                "created_by": request.user,
                                "updated_by": request.user,
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
                            module.updated_by = request.user
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
                        messages.success(request, "Module published to registry.")
                        return redirect("module-detail", module_id=module.id)
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
                                "created_by": request.user,
                                "updated_by": request.user,
                            },
                        )
                        if not created:
                            bundle.namespace = namespace
                            bundle.name = name
                            bundle.current_version = metadata.get("version", bundle.current_version)
                            bundle.bundle_spec_json = draft
                            bundle.updated_by = request.user
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
                        messages.success(request, "Bundle published to registry.")
                        return redirect("bundle-detail", bundle_id=bundle.id)

    context = {
        "session": session,
        "voice_notes": voice_notes,
        "draft_json": json.dumps(session.current_draft_json or {}, indent=2),
    }
    return render(request, "xyn/blueprint_studio.html", context)


@csrf_exempt
@login_required
def create_draft_session(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    if staff_error := _require_staff(request):
        return staff_error
    payload = json.loads(request.body.decode("utf-8"))
    name = payload.get("name") or f"Blueprint draft {uuid.uuid4()}"
    blueprint_kind = payload.get("blueprint_kind", "solution")
    context_pack_ids = payload.get("context_pack_ids") or []
    if not isinstance(context_pack_ids, list):
        return JsonResponse({"error": "context_pack_ids must be a list"}, status=400)
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
    session.save(
        update_fields=[
            "context_pack_refs_json",
            "effective_context_hash",
            "effective_context_preview",
            "updated_at",
        ]
    )
    return JsonResponse({"session_id": str(session.id)})


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
    session_id = request.POST.get("session_id")
    voice_note = VoiceNote.objects.create(
        title=request.POST.get("title", ""),
        audio_file=audio_file,
        mime_type=request.POST.get("mime_type", ""),
        duration_ms=request.POST.get("duration_ms") or None,
        language_code=request.POST.get("language_code", "en-US"),
        created_by=request.user,
    )
    if session_id:
        session = get_object_or_404(BlueprintDraftSession, id=session_id)
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
        job_id = _enqueue_job("articles.worker_tasks.transcribe_voice_note", str(voice_note.id))
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
        job_id = _enqueue_job("articles.worker_tasks.generate_blueprint_draft", str(session.id))
    else:
        session.status = "drafting"
        job_id = str(uuid.uuid4())
        _executor.submit(generate_blueprint_draft, str(session.id))
    session.job_id = job_id
    session.last_error = ""
    session.save(update_fields=["status", "job_id", "last_error"])
    return JsonResponse({"status": session.status, "job_id": job_id})


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
        job_id = _enqueue_job("articles.worker_tasks.revise_blueprint_draft", str(session.id), instruction)
    else:
        session.status = "drafting"
        job_id = str(uuid.uuid4())
        _executor.submit(revise_blueprint_draft, str(session.id), instruction)
    session.job_id = job_id
    session.last_error = ""
    session.save(update_fields=["status", "job_id", "last_error"])
    return JsonResponse({"status": session.status, "job_id": job_id})


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


@login_required
def get_draft_session(request: HttpRequest, session_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    session = get_object_or_404(BlueprintDraftSession, id=session_id)
    return JsonResponse(
        {
            "id": str(session.id),
            "blueprint_kind": session.blueprint_kind,
            "status": session.status,
            "draft": session.current_draft_json,
            "requirements_summary": session.requirements_summary,
            "validation_errors": session.validation_errors_json or [],
            "suggested_fixes": session.suggested_fixes_json or [],
            "job_id": session.job_id,
            "last_error": session.last_error,
            "diff_summary": session.diff_summary,
            "context_pack_refs": session.context_pack_refs_json or [],
            "effective_context_hash": session.effective_context_hash,
            "effective_context_preview": session.effective_context_preview,
        }
    )


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
    return JsonResponse(
        {
            "id": str(session.id),
            "blueprint_kind": session.blueprint_kind,
            "context_pack_ids": session.context_pack_ids or [],
            "requirements_summary": session.requirements_summary,
            "draft": session.current_draft_json,
            "transcripts": transcripts,
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
    session.save(
        update_fields=[
            "context_pack_refs_json",
            "effective_context_hash",
            "effective_context_preview",
            "updated_at",
        ]
    )
    return JsonResponse(
        {
            "effective_context": resolved["effective_context"],
            "context_pack_refs": resolved["refs"],
            "effective_context_hash": resolved["hash"],
            "effective_context_preview": resolved["preview"],
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
    session.save(
        update_fields=[
            "current_draft_json",
            "requirements_summary",
            "validation_errors_json",
            "suggested_fixes_json",
            "diff_summary",
            "status",
            "last_error",
            "updated_at",
        ]
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
    name = payload.get("name") or (f"Release plan for {target_fqn}" if target_fqn else "Release plan")
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
        count = Release.objects.filter(blueprint_id=blueprint_id).count() + 1
        version = f"v{count}"
    release = Release.objects.create(
        blueprint_id=blueprint_id,
        release_plan_id=release_plan_id,
        created_from_run_id=created_from_run_id,
        version=version,
        status=payload.get("status", "draft"),
        artifacts_json=payload.get("artifacts_json"),
    )
    return JsonResponse({"id": str(release.id), "version": release.version})


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
