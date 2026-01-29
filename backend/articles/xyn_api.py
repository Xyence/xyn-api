import json
from typing import Any, Dict, Optional

from django.core.paginator import Paginator
from django.db import models
from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

from .blueprints import _async_mode, _enqueue_job, _require_staff, instantiate_blueprint
from .models import Blueprint, BlueprintRevision, Bundle, Module, Registry, ReleasePlan, Run, RunArtifact


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
            defaults={"description": description, "created_by": request.user, "updated_by": request.user},
        )
        if not created:
            blueprint.description = description
            blueprint.updated_by = request.user
            blueprint.save(update_fields=["description", "updated_by", "updated_at"])
        spec_json = payload.get("spec_json")
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
        for field in ["name", "namespace", "description"]:
            if field in payload:
                setattr(blueprint, field, payload[field])
        blueprint.updated_by = request.user
        blueprint.save(update_fields=["name", "namespace", "description", "updated_by", "updated_at"])
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
        _enqueue_job("articles.worker_tasks.sync_registry", str(registry.id), str(run.id))
        return JsonResponse({"status": "queued", "run_id": str(run.id)})
    registry.last_sync_at = timezone.now()
    registry.updated_by = request.user
    registry.save(update_fields=["last_sync_at", "updated_by", "updated_at"])
    run.status = "succeeded"
    run.finished_at = timezone.now()
    run.save(update_fields=["status", "finished_at", "updated_at"])
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
            created_by=request.user,
            updated_by=request.user,
        )
        return JsonResponse({"id": str(plan.id)})
    qs = ReleasePlan.objects.all().order_by("-created_at")
    data = [
        {
            "id": str(plan.id),
            "name": plan.name,
            "target_kind": plan.target_kind,
            "target_fqn": plan.target_fqn,
            "from_version": plan.from_version,
            "to_version": plan.to_version,
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
        _enqueue_job("articles.worker_tasks.generate_release_plan", str(plan.id), str(run.id))
        return JsonResponse({"run_id": str(run.id), "status": "queued"})
    if not plan.milestones_json:
        plan.milestones_json = {"status": "placeholder", "notes": "Generation not implemented yet"}
        plan.save(update_fields=["milestones_json", "updated_at"])
    run.status = "succeeded"
    run.finished_at = timezone.now()
    run.save(update_fields=["status", "finished_at", "updated_at"])
    return JsonResponse({"run_id": str(run.id), "status": run.status})


@login_required
def runs_collection(request: HttpRequest) -> JsonResponse:
    if staff_error := _require_staff(request):
        return staff_error
    qs = Run.objects.all()
    if entity_type := request.GET.get("entity"):
        qs = qs.filter(entity_type=entity_type)
    if entity_id := request.GET.get("id"):
        qs = qs.filter(entity_id=entity_id)
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
