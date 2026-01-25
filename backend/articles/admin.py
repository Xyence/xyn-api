from django import forms
from django.contrib import admin, messages
from django.contrib.postgres.search import SearchQuery, SearchRank
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import path
from django.utils.html import strip_tags

from allauth.account.models import EmailAddress, EmailConfirmation

from .ai import generate_article_draft
from .github import index_repo, sync_orgs, sync_repos
from .models import (
    Article,
    ArticleVersion,
    GitHubConfig,
    GitHubOrganization,
    GitHubRepo,
    GitHubRepoChunk,
    OpenAIConfig,
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


@admin.register(GitHubConfig)
class GitHubConfigAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "organization_ref", "enabled", "updated_at")
    search_fields = ("name", "organization")
    actions = ["import_orgs", "sync_github_repos"]

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        form.base_fields["access_token"].widget = forms.PasswordInput(render_value=True)
        form.base_fields["access_token"].help_text = "Optional. Use PAT or connect via GitHub OAuth."
        form.base_fields["organization"].help_text = "Organization login. Use Import Orgs to select."
        if "organization_ref" in form.base_fields:
            form.base_fields["organization_ref"].help_text = "Select an imported GitHub organization."
        return form

    def save_model(self, request, obj, form, change):
        if obj.organization_ref and not obj.organization:
            obj.organization = obj.organization_ref.login
        super().save_model(request, obj, form, change)

    def import_orgs(self, request, queryset):
        total = 0
        for config in queryset:
            try:
                orgs = sync_orgs(config)
                total += len(orgs)
            except Exception as exc:
                self.message_user(request, f"Import orgs failed: {exc}", messages.ERROR)
        if total:
            self.message_user(request, f"Imported {total} organizations.", messages.SUCCESS)

    import_orgs.short_description = "Import organizations from GitHub"

    def sync_github_repos(self, request, queryset):
        total = 0
        for config in queryset:
            try:
                repos = sync_repos(config)
                total += len(repos)
            except Exception as exc:
                self.message_user(request, f"Sync failed: {exc}", messages.ERROR)
        if total:
            self.message_user(request, f"Synced {total} repositories.", messages.SUCCESS)

    sync_github_repos.short_description = "Sync repositories from GitHub"


@admin.register(GitHubRepo)
class GitHubRepoAdmin(admin.ModelAdmin):
    list_display = ("full_name", "default_branch", "is_active", "last_indexed_at")
    list_filter = ("is_active",)
    search_fields = ("full_name", "name")
    actions = ["index_selected_repos"]

    def index_selected_repos(self, request, queryset):
        total = 0
        for repo in queryset:
            total += index_repo(repo)
        self.message_user(request, f"Indexed {total} markdown chunks.", messages.SUCCESS)

    index_selected_repos.short_description = "Index selected repositories (.md files)"


@admin.register(GitHubOrganization)
class GitHubOrganizationAdmin(admin.ModelAdmin):
    list_display = ("login", "name", "config")
    search_fields = ("login", "name")


class AIStudioForm(forms.Form):
    article = forms.ModelChoiceField(queryset=Article.objects.all(), required=False)
    context_articles = forms.ModelMultipleChoiceField(
        queryset=Article.objects.none(),
        required=False,
        help_text="Optional articles to include as context.",
    )
    context_repos = forms.ModelMultipleChoiceField(
        queryset=GitHubRepo.objects.none(),
        required=False,
        help_text="Optional repositories to include as context.",
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
        self.fields["context_repos"].queryset = GitHubRepo.objects.filter(is_active=True)


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
            context_repos = form.cleaned_data["context_repos"]
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

            if context_repos:
                query = SearchQuery(prompt)
                chunks = (
                    GitHubRepoChunk.objects.filter(repo__in=context_repos)
                    .annotate(rank=SearchRank("content_search", query))
                    .filter(rank__gt=0.0)
                    .order_by("-rank")[:12]
                )
                if not chunks:
                    chunks = GitHubRepoChunk.objects.filter(repo__in=context_repos)[:6]
                for chunk in chunks:
                    context_blocks.append(
                        f"Repo: {chunk.repo.full_name}\\nPath: {chunk.path}\\nContent:\\n{chunk.content}"
                    )

            if context_blocks:
                prompt = f"{prompt}\\n\\nContext:\\n" + "\\n\\n".join(context_blocks)

            try:
                draft, _response = generate_article_draft(prompt, config, model_override)
            except Exception as exc:
                messages.error(request, f"OpenAI request failed: {exc}")
                return render(request, "admin/ai_studio.html", {"form": form, "config": config})

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

    return render(request, "admin/ai_studio.html", {"form": form, "config": config})


def _inject_ai_studio_url(urls):
    return [
        path("ai-studio/", admin.site.admin_view(ai_studio_view), name="ai-studio"),
        *urls,
    ]


admin.site.get_urls = (lambda original: (lambda: _inject_ai_studio_url(original())))(
    admin.site.get_urls
)

# Hide allauth email models from admin; user management stays under Auth.
for model in (EmailAddress, EmailConfirmation):
    try:
        admin.site.unregister(model)
    except admin.sites.NotRegistered:
        pass
