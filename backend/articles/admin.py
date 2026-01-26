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
from .models import Article, ArticleVersion, OpenAIConfig


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


class ShineSeedPlanForm(forms.Form):
    release_spec = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 18}),
        help_text="Paste a ReleaseSpec JSON document."
    )


class ShineSeedApplyForm(forms.Form):
    release_id = forms.CharField(widget=forms.HiddenInput())
    plan_id = forms.CharField(widget=forms.HiddenInput())


class ShineSeedStatusForm(forms.Form):
    release_id = forms.CharField(
        required=True,
        help_text="Release ID in the form namespace.name"
    )


def _load_runner_fixture() -> str:
    repo_root = Path(__file__).resolve().parents[3]
    fixture_path = repo_root / "xyn-contracts" / "fixtures" / "runner.release.json"
    if fixture_path.exists():
        return fixture_path.read_text()
    return json.dumps(
        {
            "apiVersion": "xyn.shineseed/v1",
            "kind": "Release",
            "metadata": {
                "name": "runner",
                "namespace": "core",
                "labels": {"app": "runner", "owner": "shineseed"},
            },
            "backend": {"type": "compose"},
            "components": [
                {
                    "name": "runner-api",
                    "image": "xyence/runner-api:dev",
                    "ports": [
                        {"name": "http", "containerPort": 8088, "hostPort": 8088, "protocol": "tcp"}
                    ],
                    "env": {
                        "RUNNER_QUEUE_URL": "redis://runner-redis:6379/0",
                        "RUNNER_WORKSPACE": "/workspace",
                        "RUNNER_LOG_LEVEL": "info",
                    },
                    "volumeMounts": [{"volume": "runner-workspace", "mountPath": "/workspace"}],
                }
            ],
            "volumes": [{"name": "runner-workspace", "type": "dockerVolume"}],
            "networks": [{"name": "runner-net", "type": "dockerNetwork"}],
        },
        indent=2,
    )


def _shineseed_request(method: str, path: str, payload=None):
    base_url = os.environ.get("SHINESEED_BASE_URL", "http://localhost:8001/api/v1")
    token = os.environ.get("SHINESEED_API_TOKEN", "").strip()
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
            raise requests.HTTPError("Authorization failed (check SHINESEED_API_TOKEN).", response=exc.response)
        raise
    return response.json()


def _format_shineseed_error(exc: Exception) -> str:
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        status_code = exc.response.status_code
        if status_code in (401, 403):
            return "ShineSeed authorization failed. Check SHINESEED_API_TOKEN."
        return f"ShineSeed request failed (HTTP {status_code})."
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


def shineseed_releases_view(request: HttpRequest) -> HttpResponse:
    plan = None
    operation = None
    status = None
    plan_form = ShineSeedPlanForm()
    apply_form = ShineSeedApplyForm()
    status_form = ShineSeedStatusForm()

    if request.method == "POST":
        action = request.POST.get("action", "plan")
        if action == "plan":
            plan_form = ShineSeedPlanForm(request.POST)
            if plan_form.is_valid():
                raw = plan_form.cleaned_data["release_spec"]
                try:
                    release_spec = json.loads(raw)
                except json.JSONDecodeError as exc:
                    messages.error(request, f"Invalid JSON: {exc.msg}")
                else:
                    try:
                        plan = _shineseed_request("post", "/releases/plan", {"release_spec": release_spec})
                        apply_form = ShineSeedApplyForm(
                            initial={
                                "release_id": plan.get("releaseId", ""),
                                "plan_id": plan.get("planId", ""),
                            }
                        )
                        status_form = ShineSeedStatusForm(
                            initial={"release_id": plan.get("releaseId", "")}
                        )
                        messages.success(request, "Plan generated successfully.")
                    except requests.RequestException as exc:
                        messages.error(request, f"ShineSeed plan failed: {_format_shineseed_error(exc)}")
        elif action == "apply":
            apply_form = ShineSeedApplyForm(request.POST)
            if apply_form.is_valid():
                release_id = apply_form.cleaned_data["release_id"]
                plan_id = apply_form.cleaned_data["plan_id"]
                try:
                    operation = _shineseed_request(
                        "post",
                        "/releases/apply",
                        {"release_id": release_id, "plan_id": plan_id},
                    )
                    status_form = ShineSeedStatusForm(initial={"release_id": release_id})
                    messages.success(request, "Apply triggered.")
                except requests.RequestException as exc:
                    messages.error(request, f"ShineSeed apply failed: {_format_shineseed_error(exc)}")
        elif action == "status":
            status_form = ShineSeedStatusForm(request.POST)
            if status_form.is_valid():
                release_id = status_form.cleaned_data["release_id"]
                try:
                    status = _shineseed_request("get", f"/releases/{release_id}/status")
                    messages.success(request, "Status refreshed.")
                except requests.RequestException as exc:
                    messages.error(request, f"Status check failed: {_format_shineseed_error(exc)}")

    if request.method == "GET":
        plan_form = ShineSeedPlanForm(initial={"release_spec": _load_runner_fixture()})

    context = {
        **admin.site.each_context(request),
        "title": "ShineSeed Releases",
        "plan_form": plan_form,
        "apply_form": apply_form,
        "status_form": status_form,
        "plan": plan,
        "operation": operation,
        "status": status,
    }
    return render(request, "admin/shineseed_releases.html", context)


def _inject_ai_studio_url(urls):
    return [
        path("ai-studio/", admin.site.admin_view(ai_studio_view), name="ai-studio"),
        path("shineseed/", admin.site.admin_view(shineseed_releases_view), name="shineseed-releases"),
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
