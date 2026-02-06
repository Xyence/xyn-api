import json
import os
import time
import uuid
from typing import Any, Dict, Optional

import requests
from django.core.paginator import Paginator
from django.db import models
from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

from xyence.middleware import _get_or_create_user_from_claims, _verify_oidc_token

from .blueprints import (
    _async_mode,
    _build_context_artifacts,
    _enqueue_job,
    _require_staff,
    _resolve_context_pack_list,
    _write_run_summary,
    instantiate_blueprint,
)
from .models import (
    Blueprint,
    BlueprintRevision,
    BlueprintDraftSession,
    DraftSessionVoiceNote,
    VoiceNote,
    Bundle,
    ContextPack,
    DevTask,
    Environment,
    Module,
    ProvisionedInstance,
    Registry,
    ReleasePlan,
    Release,
    Run,
    RunArtifact,
    RunCommandExecution,
)
from .module_registry import maybe_sync_modules_from_registry


def _parse_json(request: HttpRequest) -> Dict[str, Any]:
    if request.body:
        try:
            return json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _paginate(request: HttpRequest, qs, key: str) -> JsonResponse:
    page_size = int(request.GET.get("page_size", 20))
    page_number = int(request.GET.get("page", 1))
    paginator = Paginator(qs, page_size)
    page = paginator.get_page(page_number)
    return JsonResponse(
        {
            key: list(page.object_list),
            "count": paginator.count,
            "next": page.next_page_number() if page.has_next() else None,
            "prev": page.previous_page_number() if page.has_previous() else None,
        }
    )


_OIDC_CONFIG: Optional[Dict[str, Any]] = None
_OIDC_CONFIG_TS: float = 0.0


def _get_oidc_config(issuer: str) -> Optional[Dict[str, Any]]:
    global _OIDC_CONFIG, _OIDC_CONFIG_TS
    now = time.time()
    if _OIDC_CONFIG and now - _OIDC_CONFIG_TS < 3600:
        return _OIDC_CONFIG
    try:
        response = requests.get(f"{issuer.rstrip('/')}/.well-known/openid-configuration", timeout=10)
        response.raise_for_status()
        _OIDC_CONFIG = response.json()
        _OIDC_CONFIG_TS = now
        return _OIDC_CONFIG
    except Exception:
        return None


@csrf_exempt
def oidc_exchange(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    payload = _parse_json(request)
    code = payload.get("code")
    code_verifier = payload.get("code_verifier")
    redirect_uri = payload.get("redirect_uri")
    if not code or not code_verifier or not redirect_uri:
        return JsonResponse({"error": "code, code_verifier, and redirect_uri are required"}, status=400)
    issuer = os.environ.get("OIDC_ISSUER", "https://accounts.google.com").strip()
    client_id = os.environ.get("OIDC_CLIENT_ID", "").strip()
    client_secret = os.environ.get("OIDC_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        return JsonResponse({"error": "OIDC client not configured"}, status=500)
    config = _get_oidc_config(issuer)
    if not config or not config.get("token_endpoint"):
        return JsonResponse({"error": "OIDC configuration unavailable"}, status=502)
    try:
        token_response = requests.post(
            config["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
            timeout=15,
        )
    except Exception as exc:
        return JsonResponse({"error": f"token exchange failed: {exc}"}, status=502)
    if token_response.status_code >= 400:
        try:
            details = token_response.json()
        except Exception:
            details = token_response.text
        return JsonResponse({"error": "token exchange failed", "details": details}, status=400)
    token_payload = token_response.json()
    id_token = token_payload.get("id_token")
    if not id_token:
        return JsonResponse({"error": "id_token missing"}, status=400)
    claims = _verify_oidc_token(id_token)
    if not claims:
        return JsonResponse({"error": "invalid id_token"}, status=401)
    user = _get_or_create_user_from_claims(claims)
    if not user:
        return JsonResponse({"error": "user not allowed"}, status=403)
    return JsonResponse(
        {
            "id_token": id_token,
            "expires_in": token_payload.get("expires_in"),
        }
    )


@csrf_exempt
@login_required
def blueprints_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        name = payload.get("name")
        if not name:
            return JsonResponse({"error": "name is required"}, status=400)
        namespace = payload.get("namespace", "core")
        description = payload.get("description", "")
        blueprint, created = Blueprint.objects.get_or_create(
            name=name,
            namespace=namespace,
            defaults={
                "description": description,
                "spec_text": payload.get("spec_text", ""),
                "metadata_json": payload.get("metadata_json"),
                "created_by": request.user,
                "updated_by": request.user,
            },
        )
        if not created:
            blueprint.description = description
            if "spec_text" in payload:
                blueprint.spec_text = payload.get("spec_text", "")
            if "metadata_json" in payload:
                blueprint.metadata_json = payload.get("metadata_json")
            blueprint.updated_by = request.user
            blueprint.save(update_fields=["description", "spec_text", "metadata_json", "updated_by", "updated_at"])
        spec_json = payload.get("spec_json")
        if not spec_json and (payload.get("spec_text") or payload.get("metadata_json")):
            spec_json = {
                "spec_text": payload.get("spec_text", ""),
                "metadata": payload.get("metadata_json") or {},
            }
        if spec_json:
            revision = blueprint.revisions.order_by("-revision").first()
            next_rev = (revision.revision + 1) if revision else 1
            BlueprintRevision.objects.create(
                blueprint=blueprint,
                revision=next_rev,
                spec_json=spec_json,
                blueprint_kind=payload.get("blueprint_kind", "solution"),
                created_by=request.user,
            )
        return JsonResponse({"id": str(blueprint.id)})

    qs = Blueprint.objects.all().order_by("namespace", "name")
    if query := request.GET.get("q"):
        qs = qs.filter(models.Q(name__icontains=query) | models.Q(namespace__icontains=query))
    data = [
        {
            "id": str(b.id),
            "name": b.name,
            "namespace": b.namespace,
            "description": b.description,
            "spec_text": b.spec_text,
            "metadata_json": b.metadata_json,
            "created_at": b.created_at,
            "updated_at": b.updated_at,
            "latest_revision": b.revisions.order_by("-revision").first().revision if b.revisions.exists() else None,
        }
        for b in qs
    ]
    return _paginate(request, data, "blueprints")


@csrf_exempt
@login_required
def blueprint_detail(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    blueprint = get_object_or_404(Blueprint, id=blueprint_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        for field in ["name", "namespace", "description", "spec_text", "metadata_json"]:
            if field in payload:
                setattr(blueprint, field, payload[field])
        blueprint.updated_by = request.user
        blueprint.save(
            update_fields=["name", "namespace", "description", "spec_text", "metadata_json", "updated_by", "updated_at"]
        )
        if payload.get("spec_json"):
            revision = blueprint.revisions.order_by("-revision").first()
            next_rev = (revision.revision + 1) if revision else 1
            BlueprintRevision.objects.create(
                blueprint=blueprint,
                revision=next_rev,
                spec_json=payload.get("spec_json"),
                blueprint_kind=payload.get("blueprint_kind", "solution"),
                created_by=request.user,
            )
        return JsonResponse({"id": str(blueprint.id)})
    if request.method == "DELETE":
        blueprint.delete()
        return JsonResponse({"status": "deleted"})

    latest = blueprint.revisions.order_by("-revision").first()
    return JsonResponse(
        {
            "id": str(blueprint.id),
            "name": blueprint.name,
            "namespace": blueprint.namespace,
            "description": blueprint.description,
            "spec_text": blueprint.spec_text,
            "metadata_json": blueprint.metadata_json,
            "created_at": blueprint.created_at,
            "updated_at": blueprint.updated_at,
            "latest_revision": latest.revision if latest else None,
            "spec_json": latest.spec_json if latest else None,
        }
    )


@csrf_exempt
@login_required
def blueprint_submit(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    return instantiate_blueprint(request, blueprint_id)


@login_required
def blueprint_runs(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    runs = Run.objects.filter(entity_type="blueprint", entity_id=blueprint_id).order_by("-created_at")
    data = [
        {
            "id": str(run.id),
            "status": run.status,
            "summary": run.summary,
            "created_at": run.created_at,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
        }
        for run in runs
    ]
    return _paginate(request, data, "runs")


@csrf_exempt
@login_required
def blueprint_draft_sessions(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    blueprint = get_object_or_404(Blueprint, id=blueprint_id)
    if request.method == "POST":
        payload = _parse_json(request)
        name = payload.get("name") or f"{blueprint.namespace}.{blueprint.name} Draft"
        blueprint_kind = payload.get("blueprint_kind", "solution")
        context_pack_ids = payload.get("context_pack_ids") or []
        if not isinstance(context_pack_ids, list):
            return JsonResponse({"error": "context_pack_ids must be a list"}, status=400)
        session = BlueprintDraftSession.objects.create(
            name=name,
            blueprint=blueprint,
            blueprint_kind=blueprint_kind,
            context_pack_ids=context_pack_ids,
            created_by=request.user,
            updated_by=request.user,
        )
        return JsonResponse({"session_id": str(session.id)})
    sessions = BlueprintDraftSession.objects.filter(blueprint=blueprint).order_by("-created_at")
    data = [
        {
            "id": str(session.id),
            "name": session.name,
            "status": session.status,
            "blueprint_kind": session.blueprint_kind,
            "created_at": session.created_at,
            "updated_at": session.updated_at,
        }
        for session in sessions
    ]
    return JsonResponse({"sessions": data})


@login_required
def blueprint_voice_notes(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    sessions = BlueprintDraftSession.objects.filter(blueprint_id=blueprint_id)
    links = DraftSessionVoiceNote.objects.filter(draft_session__in=sessions).select_related(
        "voice_note", "voice_note__transcript"
    )
    data = []
    for link in links:
        note = link.voice_note
        transcript = getattr(note, "transcript", None)
        data.append(
            {
                "id": str(note.id),
                "title": note.title,
                "status": note.status,
                "created_at": note.created_at,
                "session_id": str(link.draft_session_id),
                "job_id": note.job_id,
                "last_error": note.error,
                "transcript_text": transcript.transcript_text if transcript else None,
                "transcript_confidence": transcript.confidence if transcript else None,
            }
        )
    return JsonResponse({"voice_notes": data})


@csrf_exempt
@login_required
def modules_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        name = payload.get("name")
        namespace = payload.get("namespace")
        module_type = payload.get("type")
        if not name or not namespace or not module_type:
            return JsonResponse({"error": "name, namespace, and type are required"}, status=400)
        fqn = f"{namespace}.{name}"
        module, _ = Module.objects.get_or_create(
            fqn=fqn,
            defaults={
                "name": name,
                "namespace": namespace,
                "type": module_type,
                "current_version": payload.get("current_version", "0.1.0"),
                "latest_module_spec_json": payload.get("latest_module_spec_json"),
                "created_by": request.user,
                "updated_by": request.user,
            },
        )
        if payload.get("latest_module_spec_json"):
            module.latest_module_spec_json = payload.get("latest_module_spec_json")
            module.updated_by = request.user
            module.save(update_fields=["latest_module_spec_json", "updated_by", "updated_at"])
        return JsonResponse({"id": str(module.id), "fqn": module.fqn})
    maybe_sync_modules_from_registry()
    qs = Module.objects.all().order_by("namespace", "name")
    if query := request.GET.get("q"):
        qs = qs.filter(models.Q(name__icontains=query) | models.Q(fqn__icontains=query))
    data = [
        {
            "id": str(module.id),
            "name": module.name,
            "namespace": module.namespace,
            "fqn": module.fqn,
            "type": module.type,
            "current_version": module.current_version,
            "status": module.status,
            "created_at": module.created_at,
            "updated_at": module.updated_at,
        }
        for module in qs
    ]
    return _paginate(request, data, "modules")


@csrf_exempt
@login_required
def module_detail(request: HttpRequest, module_ref: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "GET":
        maybe_sync_modules_from_registry()
    try:
        module = Module.objects.get(id=module_ref)
    except (Module.DoesNotExist, ValueError):
        module = get_object_or_404(Module, fqn=module_ref)
    if request.method == "PATCH":
        payload = _parse_json(request)
        for field in ["name", "namespace", "type", "current_version", "status", "latest_module_spec_json"]:
            if field in payload:
                setattr(module, field, payload[field])
        if "name" in payload or "namespace" in payload:
            module.fqn = f"{module.namespace}.{module.name}"
        module.updated_by = request.user
        module.save()
        return JsonResponse({"id": str(module.id)})
    if request.method == "DELETE":
        module.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(
        {
            "id": str(module.id),
            "name": module.name,
            "namespace": module.namespace,
            "fqn": module.fqn,
            "type": module.type,
            "current_version": module.current_version,
            "status": module.status,
            "latest_module_spec_json": module.latest_module_spec_json,
            "created_at": module.created_at,
            "updated_at": module.updated_at,
        }
    )


@csrf_exempt
@login_required
def bundles_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        name = payload.get("name")
        namespace = payload.get("namespace")
        if name and namespace:
            fqn = f"{namespace}.{name}"
            bundle, _ = Bundle.objects.get_or_create(
                fqn=fqn,
                defaults={
                    "name": name,
                    "namespace": namespace,
                    "current_version": payload.get("current_version", "0.1.0"),
                    "bundle_spec_json": payload.get("bundle_spec_json"),
                    "created_by": request.user,
                    "updated_by": request.user,
                },
            )
            return JsonResponse({"id": str(bundle.id), "fqn": bundle.fqn})
    qs = Bundle.objects.all().order_by("namespace", "name")
    data = [
        {
            "id": str(bundle.id),
            "name": bundle.name,
            "namespace": bundle.namespace,
            "fqn": bundle.fqn,
            "current_version": bundle.current_version,
            "status": bundle.status,
            "created_at": bundle.created_at,
            "updated_at": bundle.updated_at,
        }
        for bundle in qs
    ]
    return _paginate(request, data, "bundles")


@csrf_exempt
@login_required
def bundle_detail(request: HttpRequest, bundle_ref: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    try:
        bundle = Bundle.objects.get(id=bundle_ref)
    except (Bundle.DoesNotExist, ValueError):
        bundle = get_object_or_404(Bundle, fqn=bundle_ref)
    if request.method == "PATCH":
        payload = _parse_json(request)
        for field in ["name", "namespace", "current_version", "status", "bundle_spec_json"]:
            if field in payload:
                setattr(bundle, field, payload[field])
        if "name" in payload or "namespace" in payload:
            bundle.fqn = f"{bundle.namespace}.{bundle.name}"
        bundle.updated_by = request.user
        bundle.save()
        return JsonResponse({"id": str(bundle.id)})
    if request.method == "DELETE":
        bundle.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(
        {
            "id": str(bundle.id),
            "name": bundle.name,
            "namespace": bundle.namespace,
            "fqn": bundle.fqn,
            "current_version": bundle.current_version,
            "status": bundle.status,
            "bundle_spec_json": bundle.bundle_spec_json,
            "created_at": bundle.created_at,
            "updated_at": bundle.updated_at,
        }
    )


@csrf_exempt
@login_required
def registries_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        name = payload.get("name")
        registry_type = payload.get("registry_type")
        if not name or not registry_type:
            return JsonResponse({"error": "name and registry_type required"}, status=400)
        registry = Registry.objects.create(
            name=name,
            registry_type=registry_type,
            description=payload.get("description", ""),
            url=payload.get("url", ""),
            status=payload.get("status", "active"),
            created_by=request.user,
            updated_by=request.user,
        )
        return JsonResponse({"id": str(registry.id)})
    qs = Registry.objects.all().order_by("name")
    data = [
        {
            "id": str(registry.id),
            "name": registry.name,
            "registry_type": registry.registry_type,
            "status": registry.status,
            "last_sync_at": registry.last_sync_at,
            "created_at": registry.created_at,
            "updated_at": registry.updated_at,
        }
        for registry in qs
    ]
    return _paginate(request, data, "registries")


@csrf_exempt
@login_required
def registry_detail(request: HttpRequest, registry_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    registry = get_object_or_404(Registry, id=registry_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        for field in ["name", "registry_type", "description", "url", "status"]:
            if field in payload:
                setattr(registry, field, payload[field])
        registry.updated_by = request.user
        registry.save()
        return JsonResponse({"id": str(registry.id)})
    if request.method == "DELETE":
        registry.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(
        {
            "id": str(registry.id),
            "name": registry.name,
            "registry_type": registry.registry_type,
            "description": registry.description,
            "url": registry.url,
            "status": registry.status,
            "last_sync_at": registry.last_sync_at,
            "created_at": registry.created_at,
            "updated_at": registry.updated_at,
        }
    )


@csrf_exempt
@login_required
def registry_sync(request: HttpRequest, registry_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    registry = get_object_or_404(Registry, id=registry_id)
    run = Run.objects.create(
        entity_type="registry",
        entity_id=registry.id,
        status="pending",
        summary=f"Sync registry {registry.name}",
        created_by=request.user,
        started_at=timezone.now(),
    )
    mode = _async_mode()
    if mode == "redis":
        _enqueue_job("xyn_orchestrator.worker_tasks.sync_registry", str(registry.id), str(run.id))
        return JsonResponse({"status": "queued", "run_id": str(run.id)})
    registry.last_sync_at = timezone.now()
    registry.updated_by = request.user
    registry.save(update_fields=["last_sync_at", "updated_by", "updated_at"])
    run.status = "succeeded"
    run.finished_at = timezone.now()
    run.save(update_fields=["status", "finished_at", "updated_at"])
    _write_run_summary(run)
    return JsonResponse({"status": "synced", "last_sync_at": registry.last_sync_at, "run_id": str(run.id)})


@csrf_exempt
@login_required
def release_plans_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        name = payload.get("name")
        target_kind = payload.get("target_kind")
        target_fqn = payload.get("target_fqn")
        to_version = payload.get("to_version")
        if not name or not target_kind or not target_fqn or not to_version:
            return JsonResponse({"error": "name, target_kind, target_fqn, to_version required"}, status=400)
        plan = ReleasePlan.objects.create(
            name=name,
            target_kind=target_kind,
            target_fqn=target_fqn,
            from_version=payload.get("from_version", ""),
            to_version=to_version,
            milestones_json=payload.get("milestones_json"),
            blueprint_id=payload.get("blueprint_id"),
            environment_id=payload.get("environment_id"),
            created_by=request.user,
            updated_by=request.user,
        )
        return JsonResponse({"id": str(plan.id)})
    qs = ReleasePlan.objects.all().order_by("-created_at")
    if env_id := request.GET.get("environment_id"):
        qs = qs.filter(environment_id=env_id)
    data = [
        {
            "id": str(plan.id),
            "name": plan.name,
            "target_kind": plan.target_kind,
            "target_fqn": plan.target_fqn,
            "from_version": plan.from_version,
            "to_version": plan.to_version,
            "blueprint_id": str(plan.blueprint_id) if plan.blueprint_id else None,
            "environment_id": str(plan.environment_id) if plan.environment_id else None,
            "last_run": str(plan.last_run_id) if plan.last_run_id else None,
            "created_at": plan.created_at,
            "updated_at": plan.updated_at,
        }
        for plan in qs
    ]
    return _paginate(request, data, "release_plans")


@csrf_exempt
@login_required
def release_plan_detail(request: HttpRequest, plan_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    plan = get_object_or_404(ReleasePlan, id=plan_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        for field in ["name", "target_kind", "target_fqn", "from_version", "to_version", "milestones_json"]:
            if field in payload:
                setattr(plan, field, payload[field])
        if "blueprint_id" in payload:
            plan.blueprint_id = payload.get("blueprint_id")
        if "environment_id" in payload:
            plan.environment_id = payload.get("environment_id")
        plan.updated_by = request.user
        plan.save()
        return JsonResponse({"id": str(plan.id)})
    if request.method == "DELETE":
        plan.delete()
        return JsonResponse({"status": "deleted"})
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
            "created_at": plan.created_at,
            "updated_at": plan.updated_at,
        }
    )


@csrf_exempt
@login_required
def release_plan_generate(request: HttpRequest, plan_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    plan = get_object_or_404(ReleasePlan, id=plan_id)
    run = Run.objects.create(
        entity_type="release_plan",
        entity_id=plan.id,
        status="pending",
        summary=f"Generate release plan {plan.name}",
        created_by=request.user,
        started_at=timezone.now(),
    )
    mode = _async_mode()
    if mode == "redis":
        _enqueue_job("xyn_orchestrator.worker_tasks.generate_release_plan", str(plan.id), str(run.id))
        return JsonResponse({"run_id": str(run.id), "status": "queued"})
    if not plan.milestones_json:
        plan.milestones_json = {"status": "placeholder", "notes": "Generation not implemented yet"}
        plan.save(update_fields=["milestones_json", "updated_at"])
    run.status = "succeeded"
    run.finished_at = timezone.now()
    run.save(update_fields=["status", "finished_at", "updated_at"])
    _write_run_summary(run)
    return JsonResponse({"run_id": str(run.id), "status": run.status})


@csrf_exempt
@login_required
def releases_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        version = payload.get("version")
        if not version:
            return JsonResponse({"error": "version required"}, status=400)
        release = Release.objects.create(
            blueprint_id=payload.get("blueprint_id"),
            release_plan_id=payload.get("release_plan_id"),
            environment_id=payload.get("environment_id"),
            created_from_run_id=payload.get("created_from_run_id"),
            version=version,
            status=payload.get("status", "draft"),
            artifacts_json=payload.get("artifacts_json"),
            created_by=request.user,
            updated_by=request.user,
        )
        return JsonResponse({"id": str(release.id)})
    qs = Release.objects.all().order_by("-created_at")
    if blueprint_id := request.GET.get("blueprint_id"):
        qs = qs.filter(blueprint_id=blueprint_id)
    if env_id := request.GET.get("environment_id"):
        qs = qs.filter(environment_id=env_id)
    data = [
        {
            "id": str(release.id),
            "version": release.version,
            "status": release.status,
            "blueprint_id": str(release.blueprint_id) if release.blueprint_id else None,
            "release_plan_id": str(release.release_plan_id) if release.release_plan_id else None,
            "created_from_run_id": str(release.created_from_run_id) if release.created_from_run_id else None,
            "environment_id": str(release.environment_id) if release.environment_id else None,
            "created_at": release.created_at,
            "updated_at": release.updated_at,
        }
        for release in qs
    ]
    return _paginate(request, data, "releases")


@csrf_exempt
@login_required
def release_detail(request: HttpRequest, release_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    release = get_object_or_404(Release, id=release_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        for field in ["version", "status", "artifacts_json", "release_plan_id", "blueprint_id"]:
            if field in payload:
                setattr(release, field, payload[field])
        if "environment_id" in payload:
            release.environment_id = payload.get("environment_id")
        release.updated_by = request.user
        release.save()
        return JsonResponse({"id": str(release.id)})
    if request.method == "DELETE":
        release.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(
        {
            "id": str(release.id),
            "version": release.version,
            "status": release.status,
            "blueprint_id": str(release.blueprint_id) if release.blueprint_id else None,
            "release_plan_id": str(release.release_plan_id) if release.release_plan_id else None,
            "created_from_run_id": str(release.created_from_run_id) if release.created_from_run_id else None,
            "artifacts_json": release.artifacts_json,
            "environment_id": str(release.environment_id) if release.environment_id else None,
            "created_at": release.created_at,
            "updated_at": release.updated_at,
        }
    )


@csrf_exempt
@login_required
def environments_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        name = payload.get("name")
        slug = payload.get("slug")
        if not name or not slug:
            return JsonResponse({"error": "name and slug required"}, status=400)
        environment = Environment.objects.create(
            name=name,
            slug=slug,
            base_domain=payload.get("base_domain", ""),
            aws_region=payload.get("aws_region", ""),
        )
        return JsonResponse({"id": str(environment.id)})
    qs = Environment.objects.all().order_by("name")
    data = [
        {
            "id": str(env.id),
            "name": env.name,
            "slug": env.slug,
            "base_domain": env.base_domain,
            "aws_region": env.aws_region,
            "created_at": env.created_at,
            "updated_at": env.updated_at,
        }
        for env in qs
    ]
    return _paginate(request, data, "environments")


@csrf_exempt
@login_required
def environment_detail(request: HttpRequest, env_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    environment = get_object_or_404(Environment, id=env_id)
    if request.method == "PATCH":
        payload = _parse_json(request)
        for field in ["name", "slug", "base_domain", "aws_region"]:
            if field in payload:
                setattr(environment, field, payload[field])
        environment.save()
        return JsonResponse({"id": str(environment.id)})
    if request.method == "DELETE":
        environment.delete()
        return JsonResponse({"status": "deleted"})
    return JsonResponse(
        {
            "id": str(environment.id),
            "name": environment.name,
            "slug": environment.slug,
            "base_domain": environment.base_domain,
            "aws_region": environment.aws_region,
            "created_at": environment.created_at,
            "updated_at": environment.updated_at,
        }
    )


@login_required
def runs_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    qs = Run.objects.all()
    if entity_type := request.GET.get("entity"):
        qs = qs.filter(entity_type=entity_type)
    if entity_id := request.GET.get("id"):
        qs = qs.filter(entity_id=entity_id)
    if status := request.GET.get("status"):
        qs = qs.filter(status=status)
    data = [
        {
            "id": str(run.id),
            "entity_type": run.entity_type,
            "entity_id": str(run.entity_id),
            "status": run.status,
            "summary": run.summary,
            "created_at": run.created_at,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
        }
        for run in qs.order_by("-created_at")
    ]
    return _paginate(request, data, "runs")


@login_required
def run_detail(request: HttpRequest, run_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    run = get_object_or_404(Run, id=run_id)
    return JsonResponse(
        {
            "id": str(run.id),
            "entity_type": run.entity_type,
            "entity_id": str(run.entity_id),
            "status": run.status,
            "summary": run.summary,
            "created_at": run.created_at,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "error": run.error,
        }
    )


@login_required
def run_logs(request: HttpRequest, run_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    run = get_object_or_404(Run, id=run_id)
    return JsonResponse({"log": run.log_text, "error": run.error})


@login_required
def run_artifacts(request: HttpRequest, run_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    run = get_object_or_404(Run, id=run_id)
    artifacts = [
        {
            "id": str(artifact.id),
            "name": artifact.name,
            "kind": artifact.kind,
            "url": artifact.url,
            "metadata": artifact.metadata_json,
            "created_at": artifact.created_at,
        }
        for artifact in run.artifacts.all()
    ]
    return JsonResponse({"artifacts": artifacts})


@login_required
def run_commands(request: HttpRequest, run_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    run = get_object_or_404(Run, id=run_id)
    commands = [
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
    return JsonResponse({"commands": commands})


@csrf_exempt
@login_required
def dev_tasks_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method == "POST":
        payload = _parse_json(request)
        title = payload.get("title")
        task_type = payload.get("task_type")
        if not title or not task_type:
            return JsonResponse({"error": "title and task_type required"}, status=400)
        if task_type == "deploy_release_plan" and not payload.get("target_instance_id"):
            return JsonResponse({"error": "target_instance_id required for deploy_release_plan"}, status=400)
        release = None
        if payload.get("release_id"):
            release = get_object_or_404(Release, id=payload["release_id"])
        target_instance = None
        if payload.get("target_instance_id"):
            target_instance = get_object_or_404(ProvisionedInstance, id=payload["target_instance_id"])
            if release:
                target_instance.desired_release = release
                target_instance.save(update_fields=["desired_release", "updated_at"])
        dev_task = DevTask.objects.create(
            title=title,
            task_type=task_type,
            status=payload.get("status", "queued"),
            priority=payload.get("priority", 0),
            max_attempts=payload.get("max_attempts", 3),
            source_entity_type=payload.get("source_entity_type", "manual"),
            source_entity_id=payload.get("source_entity_id") or uuid.uuid4(),
            source_run_id=payload.get("source_run_id") or None,
            input_artifact_key=payload.get("input_artifact_key", ""),
            work_item_id=payload.get("work_item_id", ""),
            context_purpose=payload.get("context_purpose", "any"),
            target_instance=target_instance,
            force=bool(payload.get("force")),
            created_by=request.user,
            updated_by=request.user,
        )
        if pack_ids := payload.get("context_pack_ids"):
            packs = ContextPack.objects.filter(id__in=pack_ids)
            dev_task.context_packs.add(*packs)
        return JsonResponse({"id": str(dev_task.id)})
    qs = DevTask.objects.all()
    if status := request.GET.get("status"):
        qs = qs.filter(status=status)
    if task_type := request.GET.get("task_type"):
        qs = qs.filter(task_type=task_type)
    if source_entity_type := request.GET.get("source_entity_type"):
        qs = qs.filter(source_entity_type=source_entity_type)
    if source_entity_id := request.GET.get("source_entity_id"):
        qs = qs.filter(source_entity_id=source_entity_id)
    if target_instance_id := request.GET.get("target_instance_id"):
        qs = qs.filter(target_instance_id=target_instance_id)
    data = [
        {
            "id": str(task.id),
            "title": task.title,
            "task_type": task.task_type,
            "status": task.status,
            "priority": task.priority,
            "attempts": task.attempts,
            "max_attempts": task.max_attempts,
            "locked_by": task.locked_by,
            "locked_at": task.locked_at,
            "source_entity_type": task.source_entity_type,
            "source_entity_id": str(task.source_entity_id),
            "source_run": str(task.source_run_id) if task.source_run_id else None,
            "result_run": str(task.result_run_id) if task.result_run_id else None,
            "work_item_id": task.work_item_id,
            "context_purpose": task.context_purpose,
            "target_instance_id": str(task.target_instance_id) if task.target_instance_id else None,
            "force": task.force,
            "created_at": task.created_at,
            "updated_at": task.updated_at,
        }
        for task in qs.order_by("-created_at")
    ]
    return _paginate(request, data, "dev_tasks")


@login_required
def dev_task_detail(request: HttpRequest, task_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    task = get_object_or_404(DevTask, id=task_id)
    return JsonResponse(
        {
            "id": str(task.id),
            "title": task.title,
            "task_type": task.task_type,
            "status": task.status,
            "priority": task.priority,
            "attempts": task.attempts,
            "max_attempts": task.max_attempts,
            "locked_by": task.locked_by,
            "locked_at": task.locked_at,
            "source_entity_type": task.source_entity_type,
            "source_entity_id": str(task.source_entity_id),
            "source_run": str(task.source_run_id) if task.source_run_id else None,
            "result_run": str(task.result_run_id) if task.result_run_id else None,
            "input_artifact_key": task.input_artifact_key,
            "work_item_id": task.work_item_id,
            "last_error": task.last_error,
            "context_purpose": task.context_purpose,
            "target_instance_id": str(task.target_instance_id) if task.target_instance_id else None,
            "force": task.force,
            "context_packs": [
                {
                    "id": str(pack.id),
                    "name": pack.name,
                    "purpose": pack.purpose,
                    "scope": pack.scope,
                    "version": pack.version,
                }
                for pack in task.context_packs.all()
            ],
            "created_at": task.created_at,
            "updated_at": task.updated_at,
        }
    )


@csrf_exempt
@login_required
def dev_task_run(request: HttpRequest, task_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    task = get_object_or_404(DevTask, id=task_id)
    if task.status == "running":
        return JsonResponse({"error": "Task already running"}, status=409)
    if task.task_type == "deploy_release_plan" and not task.target_instance_id:
        return JsonResponse({"error": "target_instance_id required for deploy_release_plan"}, status=400)
    if request.GET.get("force") == "1":
        task.force = True
    task.force = bool(task.force)
    task.status = "queued"
    task.updated_by = request.user
    task.save(update_fields=["status", "updated_by", "updated_at", "force"])
    run = Run.objects.create(
        entity_type="dev_task",
        entity_id=task.id,
        status="pending",
        summary=f"Run dev task {task.title}",
        created_by=request.user,
        started_at=timezone.now(),
    )
    task.result_run = run
    task.save(update_fields=["result_run", "updated_at"])
    resolved = _resolve_context_pack_list(list(task.context_packs.all()))
    run.context_pack_refs_json = resolved.get("refs", [])
    run.context_hash = resolved.get("hash", "")
    _build_context_artifacts(run, resolved)
    run.save(update_fields=["context_pack_refs_json", "context_hash", "updated_at"])
    mode = _async_mode()
    if mode == "redis":
        _enqueue_job("xyn_orchestrator.worker_tasks.run_dev_task", str(task.id), "worker")
        return JsonResponse({"run_id": str(run.id), "status": "queued"})
    return JsonResponse({"run_id": str(run.id), "status": "pending"})


@csrf_exempt
@login_required
def dev_task_retry(request: HttpRequest, task_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    task = get_object_or_404(DevTask, id=task_id)
    if task.status not in {"failed", "canceled"}:
        return JsonResponse({"error": "Task not retryable"}, status=409)
    task.status = "queued"
    task.updated_by = request.user
    task.save(update_fields=["status", "updated_by", "updated_at"])
    run = Run.objects.create(
        entity_type="dev_task",
        entity_id=task.id,
        status="pending",
        summary=f"Retry dev task {task.title}",
        created_by=request.user,
        started_at=timezone.now(),
    )
    task.result_run = run
    task.save(update_fields=["result_run", "updated_at"])
    resolved = _resolve_context_pack_list(list(task.context_packs.all()))
    run.context_pack_refs_json = resolved.get("refs", [])
    run.context_hash = resolved.get("hash", "")
    _build_context_artifacts(run, resolved)
    run.save(update_fields=["context_pack_refs_json", "context_hash", "updated_at"])
    mode = _async_mode()
    if mode == "redis":
        _enqueue_job("xyn_orchestrator.worker_tasks.run_dev_task", str(task.id), "worker")
        return JsonResponse({"run_id": str(run.id), "status": "queued"})
    return JsonResponse({"run_id": str(run.id), "status": "pending"})


@csrf_exempt
@login_required
def dev_task_cancel(request: HttpRequest, task_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    task = get_object_or_404(DevTask, id=task_id)
    if task.status in {"succeeded", "failed", "canceled"}:
        return JsonResponse({"status": task.status})
    task.status = "canceled"
    task.updated_by = request.user
    task.save(update_fields=["status", "updated_by", "updated_at"])
    return JsonResponse({"status": "canceled"})


@login_required
def blueprint_dev_tasks(request: HttpRequest, blueprint_id: str) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    tasks = DevTask.objects.filter(source_entity_type="blueprint", source_entity_id=blueprint_id).order_by(
        "-created_at"
    )
    data = [
        {
            "id": str(task.id),
            "title": task.title,
            "task_type": task.task_type,
            "status": task.status,
            "priority": task.priority,
            "attempts": task.attempts,
            "max_attempts": task.max_attempts,
            "result_run": str(task.result_run_id) if task.result_run_id else None,
            "created_at": task.created_at,
        }
        for task in tasks
    ]
    return JsonResponse({"dev_tasks": data})
