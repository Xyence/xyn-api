import json
import os
from pathlib import Path

import requests
from django import forms
from django.contrib import admin, messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import path
from django.utils.html import strip_tags

from allauth.account.models import EmailAddress, EmailConfirmation
from django.contrib.sites.models import Site

from .ai import generate_article_draft
from .models import (
    Article,
    ArticleVersion,
    Blueprint,
    BlueprintDraftSession,
    BlueprintInstance,
    BlueprintRevision,
    Bundle,
    Environment,
    Registry,
    Run,
    RunArtifact,
    RunCommandExecution,
    Capability,
    ContextPack,
    DraftSessionVoiceNote,
    DevTask,
    Module,
    OpenAIConfig,
    ProvisionedInstance,
    ReleasePlan,
    Release,
    ReleasePlanDeployState,
    ReleasePlanDeployment,
    VoiceNote,
    VoiceTranscript,
)


class ArticleVersionInline(admin.TabularInline):
    model = ArticleVersion
    extra = 0
    fields = ("version_number", "source", "model_name", "created_at")
    readonly_fields = ("version_number", "source", "model_name", "created_at")


@admin.register(Article)
class ArticleAdmin(admin.ModelAdmin):
    list_display = ("title", "status", "published_at", "updated_at")
    list_filter = ("status",)
    search_fields = ("title", "summary")
    prepopulated_fields = {"slug": ("title",)}
    ordering = ("-published_at", "-created_at")
    inlines = [ArticleVersionInline]
    actions = ["create_version_snapshot"]

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if obj.status == "published":
            obj.create_version_if_changed(source="manual")

    def create_version_snapshot(self, request, queryset):
        created = 0
        for article in queryset:
            if article.create_version_if_changed(source="manual"):
                created += 1
        self.message_user(request, f"Created {created} version snapshot(s).", messages.SUCCESS)

    create_version_snapshot.short_description = "Create version snapshot(s)"


@admin.register(ArticleVersion)
class ArticleVersionAdmin(admin.ModelAdmin):
    list_display = ("article", "version_number", "source", "model_name", "created_at")
    list_filter = ("source",)
    search_fields = ("article__title", "summary")
    readonly_fields = ("version_number", "created_at")
    actions = ["apply_version_to_article"]

    def apply_version_to_article(self, request, queryset):
        updated = 0
        for version in queryset:
            article = version.article
            article.title = version.title
            article.summary = version.summary
            article.body = version.body
            if article.status != "published":
                article.status = "draft"
            article.save()
            updated += 1
        self.message_user(request, f"Applied {updated} version(s) to articles.", messages.SUCCESS)

    apply_version_to_article.short_description = "Apply selected versions to their articles"


@admin.register(OpenAIConfig)
class OpenAIConfigAdmin(admin.ModelAdmin):
    list_display = ("name", "default_model", "updated_at")
    search_fields = ("name", "default_model")

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        form.base_fields["api_key"].widget = forms.PasswordInput(render_value=True)
        return form


@admin.register(Blueprint)
class BlueprintAdmin(admin.ModelAdmin):
    list_display = ("namespace", "name", "created_at", "updated_at")
    search_fields = ("name", "namespace")


@admin.register(BlueprintRevision)
class BlueprintRevisionAdmin(admin.ModelAdmin):
    list_display = ("blueprint", "revision", "blueprint_kind", "created_at")
    search_fields = ("blueprint__name",)


@admin.register(BlueprintDraftSession)
class BlueprintDraftSessionAdmin(admin.ModelAdmin):
    list_display = ("name", "blueprint", "blueprint_kind", "status", "job_id", "updated_at")
    search_fields = ("name", "blueprint__name")


@admin.register(DraftSessionVoiceNote)
class DraftSessionVoiceNoteAdmin(admin.ModelAdmin):
    list_display = ("draft_session", "voice_note", "ordering")


@admin.register(VoiceNote)
class VoiceNoteAdmin(admin.ModelAdmin):
    list_display = ("title", "status", "job_id", "created_at")
    search_fields = ("title",)


@admin.register(VoiceTranscript)
class VoiceTranscriptAdmin(admin.ModelAdmin):
    list_display = ("voice_note", "provider", "created_at")


@admin.register(BlueprintInstance)
class BlueprintInstanceAdmin(admin.ModelAdmin):
    list_display = ("blueprint", "revision", "status", "created_at")


@admin.register(Module)
class ModuleAdmin(admin.ModelAdmin):
    list_display = ("fqn", "type", "current_version", "status", "updated_at")
    search_fields = ("name", "namespace", "fqn")
    list_filter = ("type", "status")


@admin.register(Bundle)
class BundleAdmin(admin.ModelAdmin):
    list_display = ("fqn", "current_version", "status", "updated_at")
    search_fields = ("name", "namespace", "fqn")
    list_filter = ("status",)


@admin.register(Capability)
class CapabilityAdmin(admin.ModelAdmin):
    list_display = ("name", "version", "updated_at")
    search_fields = ("name",)


@admin.register(Environment)
class EnvironmentAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "base_domain", "aws_region", "updated_at")
    search_fields = ("name", "slug", "base_domain")


@admin.register(ReleasePlan)
class ReleasePlanAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "target_kind",
        "target_fqn",
        "from_version",
        "to_version",
        "blueprint",
        "environment",
        "updated_at",
    )
    search_fields = ("name", "target_fqn")
    list_filter = ("target_kind", "environment")


@admin.register(Release)
class ReleaseAdmin(admin.ModelAdmin):
    list_display = ("version", "status", "blueprint", "release_plan", "environment", "updated_at")
    list_filter = ("status", "environment")
    search_fields = ("version",)


@admin.register(ContextPack)
class ContextPackAdmin(admin.ModelAdmin):
    list_display = ("name", "purpose", "scope", "version", "is_active", "is_default", "updated_at")
    search_fields = ("name", "namespace", "project_key")
    list_filter = ("purpose", "scope", "is_active", "is_default")


@admin.register(DevTask)
class DevTaskAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "task_type",
        "status",
        "priority",
        "attempts",
        "locked_by",
        "target_instance",
        "updated_at",
    )
    search_fields = ("title", "source_entity_type", "source_entity_id")
    list_filter = ("task_type", "status")


@admin.register(Registry)
class RegistryAdmin(admin.ModelAdmin):
    list_display = ("name", "registry_type", "status", "last_sync_at")
    list_filter = ("registry_type", "status")
    search_fields = ("name", "url")


@admin.register(Run)
class RunAdmin(admin.ModelAdmin):
    list_display = ("entity_type", "entity_id", "status", "created_at", "finished_at")
    list_filter = ("entity_type", "status")
    search_fields = ("entity_id", "summary")


@admin.register(RunArtifact)
class RunArtifactAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "run", "created_at")


@admin.register(RunCommandExecution)
class RunCommandExecutionAdmin(admin.ModelAdmin):
    list_display = ("run", "step_name", "command_index", "status", "exit_code", "ssm_command_id")
    list_filter = ("status", "shell")
    search_fields = ("step_name", "ssm_command_id", "run__id")


@admin.register(ReleasePlanDeployState)
class ReleasePlanDeployStateAdmin(admin.ModelAdmin):
    list_display = ("release_plan", "instance", "last_applied_hash", "last_applied_at", "updated_at")
    search_fields = ("release_plan__name", "instance__name")


@admin.register(ReleasePlanDeployment)
class ReleasePlanDeploymentAdmin(admin.ModelAdmin):
    list_display = ("release_plan", "instance", "last_applied_hash", "last_applied_at", "updated_at")
    search_fields = ("release_plan__name", "instance__name")


@admin.register(ProvisionedInstance)
class ProvisionedInstanceAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "environment",
        "aws_region",
        "instance_id",
        "status",
        "health_status",
        "desired_release",
        "observed_release",
        "public_ip",
        "updated_at",
    )
    search_fields = ("name", "instance_id", "public_ip", "private_ip")
    list_filter = ("status", "aws_region", "environment")




class AIStudioForm(forms.Form):
    article = forms.ModelChoiceField(queryset=Article.objects.all(), required=False)
    context_articles = forms.ModelMultipleChoiceField(
        queryset=Article.objects.none(),
        required=False,
        help_text="Optional articles to include as context.",
    )
    prompt = forms.CharField(widget=forms.Textarea(attrs={"rows": 8}))
    persistent_context = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 6}),
        help_text="Stored in OpenAI Config for reuse.",
    )
    model_override = forms.CharField(required=False, help_text="Optional model override.")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["context_articles"].queryset = Article.objects.all()


class XynSeedPlanForm(forms.Form):
    release_spec = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 18}),
        help_text="Paste a ReleaseSpec JSON document."
    )


class XynSeedApplyForm(forms.Form):
    release_id = forms.CharField(widget=forms.HiddenInput())
    plan_id = forms.CharField(widget=forms.HiddenInput())


class XynSeedStatusForm(forms.Form):
    release_id = forms.CharField(
        required=True,
        help_text="Release ID in the form namespace.name"
    )


class XynSeedStopForm(forms.Form):
    release_id = forms.CharField(widget=forms.HiddenInput())
    confirm_stop = forms.BooleanField(required=False)


class XynSeedRestartForm(forms.Form):
    release_id = forms.CharField(widget=forms.HiddenInput())
    service_name = forms.CharField(required=True)


class XynSeedDestroyForm(forms.Form):
    release_id = forms.CharField(widget=forms.HiddenInput())
    remove_volumes = forms.BooleanField(required=False)
    confirm_destroy = forms.BooleanField(required=False)
    confirm_text = forms.CharField(required=False)

def _load_runner_fixture() -> str:
    fixture_root = os.environ.get("XYNSEED_CONTRACTS_ROOT", "").strip()
    if fixture_root:
        fixture_path = Path(fixture_root) / "fixtures" / "runner.release.json"
        if fixture_path.exists():
            return fixture_path.read_text()

    current = Path(__file__).resolve()
    fixture_path = None
    for parent in current.parents:
        candidate = parent / "xyn-contracts" / "fixtures" / "runner.release.json"
        if candidate.exists():
            fixture_path = candidate
            break

    if fixture_path and fixture_path.exists():
        return fixture_path.read_text()

    return json.dumps(
        {
            "apiVersion": "xyn.seed/v1",
            "kind": "Release",
            "metadata": {
                "name": "runner",
                "namespace": "core",
                "labels": {"app": "runner", "owner": "xyn-seed"},
            },
            "backend": {"type": "compose"},
            "components": [
                {
                    "name": "runner-api",
                    "image": "xyence/xyn-runner-api:git-b56708f",
                    "ports": [
                        {"name": "http", "containerPort": 8088, "hostPort": 8088, "protocol": "tcp"}
                    ],
                    "env": {
                        "RUNNER_REDIS_URL": "redis://runner-redis:6379/0",
                        "RUNNER_QUEUE_NAME": "default",
                        "RUNNER_WORKSPACE": "/workspace",
                        "RUNNER_LOG_LEVEL": "info",
                    },
                    "volumeMounts": [{"volume": "runner-workspace", "mountPath": "/workspace"}],
                },
                {
                    "name": "runner-worker",
                    "image": "xyence/xyn-runner-worker:git-b56708f",
                    "env": {
                        "RUNNER_REDIS_URL": "redis://runner-redis:6379/0",
                        "RUNNER_QUEUE_NAME": "default",
                        "RUNNER_WORKSPACE": "/workspace",
                        "RUNNER_LOG_LEVEL": "info",
                    },
                    "volumeMounts": [{"volume": "runner-workspace", "mountPath": "/workspace"}],
                    "dependsOn": ["runner-redis"],
                },
                {
                    "name": "runner-redis",
                    "image": "redis:7-alpine",
                    "healthcheck": {
                        "test": ["CMD", "redis-cli", "ping"],
                        "interval": "10s",
                        "timeout": "5s",
                        "retries": 5,
                    },
                    "ports": [
                        {"name": "redis", "containerPort": 6379, "hostPort": 6379, "protocol": "tcp"}
                    ],
                },
            ],
            "volumes": [{"name": "runner-workspace", "type": "dockerVolume"}],
            "networks": [{"name": "runner-net", "type": "dockerNetwork"}],
        },
        indent=2,
    )


def _xyn_seed_request(method: str, path: str, payload=None):
    base_url = os.environ.get("XYNSEED_BASE_URL", "").strip() or "http://localhost:8001/api/v1"
    token = os.environ.get("XYNSEED_API_TOKEN", "").strip()
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.request(
        method=method,
        url=f"{base_url}{path}",
        json=payload,
        headers=headers,
        timeout=15
    )
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response else None
        if status_code in (401, 403):
            raise requests.HTTPError("Authorization failed (check XYNSEED_API_TOKEN).", response=exc.response)
        raise
    return response.json()


def _xyn_seed_request_text(method: str, path: str, payload=None) -> str:
    base_url = os.environ.get("XYNSEED_BASE_URL", "").strip() or "http://localhost:8001/api/v1"
    token = os.environ.get("XYNSEED_API_TOKEN", "").strip()
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.request(
        method=method,
        url=f"{base_url}{path}",
        json=payload,
        headers=headers,
        timeout=15
    )
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response else None
        if status_code in (401, 403):
            raise requests.HTTPError("Authorization failed (check XYNSEED_API_TOKEN).", response=exc.response)
        raise
    return response.text


def _format_xyn_seed_error(exc: Exception) -> str:
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        status_code = exc.response.status_code
        if status_code in (401, 403):
            return "Xyn Seed authorization failed. Check XYNSEED_API_TOKEN."
        return f"Xyn Seed request failed (HTTP {status_code})."
    return str(exc)


def ai_studio_view(request: HttpRequest) -> HttpResponse:
    config = OpenAIConfig.objects.first()
    if not config:
        messages.error(request, "Create an OpenAI Config before using AI Studio.")
        return redirect("/admin/articles/openaiconfig/")

    if request.method == "POST":
        form = AIStudioForm(request.POST)
        if form.is_valid():
            article = form.cleaned_data["article"]
            context_articles = form.cleaned_data["context_articles"]
            prompt = form.cleaned_data["prompt"]
            persistent_context = form.cleaned_data["persistent_context"]
            model_override = form.cleaned_data["model_override"] or None

            if persistent_context is not None:
                config.persistent_context = persistent_context
                config.save(update_fields=["persistent_context"])

            context_blocks = []
            if config.persistent_context:
                context_blocks.append(f"Persistent context:\\n{config.persistent_context}")

            for ctx_article in context_articles:
                clean_body = strip_tags(ctx_article.body or "")
                excerpt = clean_body[:2000]
                context_blocks.append(
                    f"Article context: {ctx_article.title}\\nSummary: {ctx_article.summary}\\nExcerpt: {excerpt}"
                )

            if context_blocks:
                prompt = f"{prompt}\\n\\nContext:\\n" + "\\n\\n".join(context_blocks)

            try:
                draft, _response = generate_article_draft(prompt, config, model_override)
            except Exception as exc:
                messages.error(request, f"OpenAI request failed: {exc}")
                context = {
                    **admin.site.each_context(request),
                    "form": form,
                    "config": config,
                    "title": "AI Studio",
                }
                return render(request, "admin/ai_studio.html", context)

            title = draft.get("title") or "Untitled draft"
            summary = draft.get("summary", "")
            body = draft.get("body_html", "")

            if not article:
                article = Article.objects.create(
                    title=title,
                    summary=summary,
                    body=body,
                    status="draft",
                )
            else:
                article.title = title
                article.summary = summary
                article.body = body
                if article.status != "published":
                    article.status = "draft"
                article.save()

            ArticleVersion.objects.create(
                article=article,
                title=title,
                summary=summary,
                body=body,
                source="ai",
                prompt=prompt,
                model_name=model_override or config.default_model,
            )

            messages.success(request, "Draft saved. Review in the article editor.")
            return redirect(f"/admin/articles/article/{article.id}/change/")
    else:
        form = AIStudioForm(
            initial={"persistent_context": config.persistent_context},
        )

    context = {
        **admin.site.each_context(request),
        "form": form,
        "config": config,
        "title": "AI Studio",
    }
    return render(request, "admin/ai_studio.html", context)


def xyn_seed_releases_view(request: HttpRequest) -> HttpResponse:
    plan = None
    operation = None
    status = None
    releases = []
    release_details = None
    release_spec_json = None
    operations = []
    logs = None
    plan_form = XynSeedPlanForm()
    apply_form = XynSeedApplyForm()
    status_form = XynSeedStatusForm()
    stop_form = XynSeedStopForm()
    restart_form = XynSeedRestartForm()
    destroy_form = XynSeedDestroyForm()
    selected_release_id = request.GET.get("release_id")
    logs_operation_id = request.GET.get("op_id")

    if request.method == "POST":
        action = request.POST.get("action", "plan")
        if action == "plan":
            plan_form = XynSeedPlanForm(request.POST)
            if plan_form.is_valid():
                raw = plan_form.cleaned_data["release_spec"]
                try:
                    release_spec = json.loads(raw)
                except json.JSONDecodeError as exc:
                    messages.error(request, f"Invalid JSON: {exc.msg}")
                else:
                    try:
                        plan = _xyn_seed_request("post", "/releases/plan", {"release_spec": release_spec})
                        apply_form = XynSeedApplyForm(
                            initial={
                                "release_id": plan.get("releaseId", ""),
                                "plan_id": plan.get("planId", ""),
                            }
                        )
                        status_form = XynSeedStatusForm(
                            initial={"release_id": plan.get("releaseId", "")}
                        )
                        selected_release_id = plan.get("releaseId")
                        messages.success(request, "Plan generated successfully.")
                    except requests.RequestException as exc:
                        messages.error(request, f"Xyn Seed plan failed: {_format_xyn_seed_error(exc)}")
        elif action == "apply":
            apply_form = XynSeedApplyForm(request.POST)
            if apply_form.is_valid():
                release_id = apply_form.cleaned_data["release_id"]
                plan_id = apply_form.cleaned_data["plan_id"]
                try:
                    operation = _xyn_seed_request(
                        "post",
                        "/releases/apply",
                        {"release_id": release_id, "plan_id": plan_id},
                    )
                    status_form = XynSeedStatusForm(initial={"release_id": release_id})
                    selected_release_id = release_id
                    messages.success(request, "Apply triggered.")
                except requests.RequestException as exc:
                    messages.error(request, f"Xyn Seed apply failed: {_format_xyn_seed_error(exc)}")
        elif action == "status":
            status_form = XynSeedStatusForm(request.POST)
            if status_form.is_valid():
                release_id = status_form.cleaned_data["release_id"]
                try:
                    status = _xyn_seed_request("get", f"/releases/{release_id}/status")
                    selected_release_id = release_id
                    messages.success(request, "Status refreshed.")
                except requests.RequestException as exc:
                    messages.error(request, f"Status check failed: {_format_xyn_seed_error(exc)}")
        elif action == "plan_stop":
            stop_form = XynSeedStopForm(request.POST)
            if stop_form.is_valid():
                release_id = stop_form.cleaned_data["release_id"]
                if not stop_form.cleaned_data.get("confirm_stop"):
                    messages.error(request, "Confirm stop before planning.")
                else:
                    try:
                        plan = _xyn_seed_request("post", f"/releases/{release_id}/plan/stop")
                        apply_form = XynSeedApplyForm(
                            initial={"release_id": release_id, "plan_id": plan.get("planId", "")}
                        )
                        selected_release_id = release_id
                        messages.success(request, "Stop plan generated.")
                    except requests.RequestException as exc:
                        messages.error(request, f"Xyn Seed stop plan failed: {_format_xyn_seed_error(exc)}")
        elif action == "plan_restart":
            restart_form = XynSeedRestartForm(request.POST)
            if restart_form.is_valid():
                release_id = restart_form.cleaned_data["release_id"]
                service_name = restart_form.cleaned_data["service_name"]
                try:
                    plan = _xyn_seed_request(
                        "post",
                        f"/releases/{release_id}/plan/restart",
                        {"serviceName": service_name},
                    )
                    apply_form = XynSeedApplyForm(
                        initial={"release_id": release_id, "plan_id": plan.get("planId", "")}
                    )
                    selected_release_id = release_id
                    messages.success(request, "Restart plan generated.")
                except requests.RequestException as exc:
                    messages.error(request, f"Xyn Seed restart plan failed: {_format_xyn_seed_error(exc)}")
        elif action == "plan_destroy":
            destroy_form = XynSeedDestroyForm(request.POST)
            if destroy_form.is_valid():
                release_id = destroy_form.cleaned_data["release_id"]
                confirm_text = destroy_form.cleaned_data.get("confirm_text", "")
                if not destroy_form.cleaned_data.get("confirm_destroy") or confirm_text != release_id:
                    messages.error(request, "Confirm destroy by typing the release ID.")
                else:
                    remove_volumes = destroy_form.cleaned_data.get("remove_volumes", False)
                    try:
                        plan = _xyn_seed_request(
                            "post",
                            f"/releases/{release_id}/plan/destroy",
                            {"removeVolumes": remove_volumes},
                        )
                        apply_form = XynSeedApplyForm(
                            initial={"release_id": release_id, "plan_id": plan.get("planId", "")}
                        )
                        selected_release_id = release_id
                        messages.success(request, "Destroy plan generated.")
                    except requests.RequestException as exc:
                        messages.error(request, f"Xyn Seed destroy plan failed: {_format_xyn_seed_error(exc)}")

    if request.method == "GET":
        plan_form = XynSeedPlanForm(initial={"release_spec": _load_runner_fixture()})

    try:
        releases = _xyn_seed_request("get", "/releases")
    except requests.RequestException as exc:
        messages.error(request, f"Release list failed: {_format_xyn_seed_error(exc)}")

    if selected_release_id:
        try:
            release_details = _xyn_seed_request("get", f"/releases/{selected_release_id}")
            release_spec_json = json.dumps(release_details.get("releaseSpec", {}), indent=2)
            status = _xyn_seed_request("get", f"/releases/{selected_release_id}/status")
            operations = _xyn_seed_request("get", f"/releases/{selected_release_id}/operations")
            status_form = XynSeedStatusForm(initial={"release_id": selected_release_id})
            stop_form = XynSeedStopForm(initial={"release_id": selected_release_id})
            restart_form = XynSeedRestartForm(initial={"release_id": selected_release_id})
            destroy_form = XynSeedDestroyForm(initial={"release_id": selected_release_id})
        except requests.RequestException as exc:
            messages.error(request, f"Release detail failed: {_format_xyn_seed_error(exc)}")

    if logs_operation_id:
        try:
            logs = _xyn_seed_request_text("get", f"/operations/{logs_operation_id}/logs")
        except requests.RequestException as exc:
            messages.error(request, f"Log fetch failed: {_format_xyn_seed_error(exc)}")

    context = {
        **admin.site.each_context(request),
        "title": "Xyn Seed Releases",
        "plan_form": plan_form,
        "apply_form": apply_form,
        "status_form": status_form,
        "stop_form": stop_form,
        "restart_form": restart_form,
        "destroy_form": destroy_form,
        "plan": plan,
        "operation": operation,
        "status": status,
        "releases": releases,
        "release_details": release_details,
        "operations": operations,
        "selected_release_id": selected_release_id,
        "logs": logs,
        "logs_operation_id": logs_operation_id,
        "release_spec_json": release_spec_json,
    }
    return render(request, "admin/xyn_seed_releases.html", context)


def xyn_seed_artifact_view(request: HttpRequest, release_id: str, artifact_kind: str) -> HttpResponse:
    try:
        content = _xyn_seed_request_text("get", f"/releases/{release_id}/artifacts/{artifact_kind}")
    except requests.RequestException as exc:
        messages.error(request, f"Artifact download failed: {_format_xyn_seed_error(exc)}")
        return redirect(f"/admin/xyn-seed/?release_id={release_id}")

    content_type = "application/json" if artifact_kind in ("releaseSpec", "runtimeSpec") else "text/plain"
    return HttpResponse(content, content_type=content_type)


def _inject_ai_studio_url(urls):
    return [
        path("ai-studio/", admin.site.admin_view(ai_studio_view), name="ai-studio"),
        path("xyn-seed/", admin.site.admin_view(xyn_seed_releases_view), name="xyn-seed-releases"),
        path(
            "xyn-seed/artifacts/<str:release_id>/<str:artifact_kind>/",
            admin.site.admin_view(xyn_seed_artifact_view),
            name="xyn-seed-artifact",
        ),
        *urls,
    ]


admin.site.get_urls = (lambda original: (lambda: _inject_ai_studio_url(original())))(
    admin.site.get_urls
)

# Hide allauth email models and sites from admin; user management stays under Auth.
for model in (EmailAddress, EmailConfirmation, Site):
    try:
        admin.site.unregister(model)
    except admin.sites.NotRegistered:
        pass
