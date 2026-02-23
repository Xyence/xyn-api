from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_GET

from .models import (
    Article,
    Artifact,
    ArtifactExternalRef,
    ArtifactRevision,
    PublishBinding,
)


def _public_article_queryset():
    return (
        Artifact.objects.filter(type__slug="article", status="published", visibility="public")
        .select_related("workspace", "type", "article_category")
        .order_by("-published_at", "-created_at")
    )


def _latest_revision(artifact: Artifact):
    return artifact.revisions.order_by("-revision_number").first()


def _normalized_surface_path(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return "/articles"
    return value if value.startswith("/") else f"/{value}"


def _artifact_matches_surface(artifact: Artifact, surface_path: str) -> bool:
    normalized = _normalized_surface_path(surface_path)
    article_binding_exists = PublishBinding.objects.filter(
        scope_type="article",
        scope_id=artifact.id,
        target_type__in=["xyn_ui_route", "public_web_path"],
        target_value=normalized,
        enabled=True,
    ).exists()
    if article_binding_exists:
        return True
    if artifact.article_category_id:
        category_binding_exists = PublishBinding.objects.filter(
            scope_type="category",
            scope_id=artifact.article_category_id,
            target_type__in=["xyn_ui_route", "public_web_path"],
            target_value=normalized,
            enabled=True,
        ).exists()
        if category_binding_exists:
            return True
    # Legacy fallback for /articles: include only web-category artifacts when bindings are absent.
    if normalized == "/articles":
        category_slug = ""
        if artifact.article_category_id and artifact.article_category:
            category_slug = str(artifact.article_category.slug or "").strip().lower()
        if not category_slug:
            category_slug = str((artifact.scope_json or {}).get("category") or "").strip().lower()
        return category_slug == "web"
    return False


@require_GET
def public_articles(request):
    surface_path = _normalized_surface_path(str(request.GET.get("surface_path") or "/articles"))
    queryset = [artifact for artifact in _public_article_queryset() if _artifact_matches_surface(artifact, surface_path)]
    page_size = int(request.GET.get("page_size", 10))
    page_number = int(request.GET.get("page", 1))
    paginator = Paginator(queryset, page_size)
    page = paginator.get_page(page_number)

    items = []
    for artifact in page.object_list:
        revision = _latest_revision(artifact)
        content = (revision.content_json if revision else {}) or {}
        slug_ref = ArtifactExternalRef.objects.filter(artifact=artifact).exclude(slug_path="").order_by("created_at").first()
        slug = artifact.slug or (slug_ref.slug_path if slug_ref else "") or str((artifact.scope_json or {}).get("slug") or "")
        items.append(
            {
                "title": artifact.title,
                "slug": slug,
                "summary": str(content.get("summary") or (artifact.scope_json or {}).get("summary") or ""),
                "published_at": artifact.published_at,
                "updated_at": artifact.updated_at,
            }
        )

    if paginator.count == 0:
        # Backward-compatible fallback for pre-migration environments.
        legacy = Article.objects.filter(status="published").order_by("-published_at", "-created_at")
        legacy_paginator = Paginator(legacy, page_size)
        legacy_page = legacy_paginator.get_page(page_number)
        items = [
            {
                "title": article.title,
                "slug": article.slug,
                "summary": article.summary,
                "published_at": article.published_at,
                "updated_at": article.updated_at,
            }
            for article in legacy_page.object_list
        ]
        paginator = legacy_paginator
        page = legacy_page

    payload = {
        "items": items,
        "count": paginator.count,
        "next": page.next_page_number() if page.has_next() else None,
        "prev": page.previous_page_number() if page.has_previous() else None,
    }
    return JsonResponse(payload)


@require_GET
def public_article_detail(request, slug: str):
    surface_path = str(request.GET.get("surface_path") or "").strip()
    artifact = (
        Artifact.objects.filter(type__slug="article", status="published", visibility="public", slug=slug)
        .select_related("workspace", "type")
        .first()
    )
    if artifact and (not surface_path or _artifact_matches_surface(artifact, surface_path)):
        revision = _latest_revision(artifact)
        content = (revision.content_json if revision else {}) or {}
        summary = str(content.get("summary") or (artifact.scope_json or {}).get("summary") or "")
        payload = {
            "title": content.get("title") or artifact.title,
            "slug": slug,
            "summary": summary,
            "published_at": artifact.published_at,
            "updated_at": artifact.updated_at,
            "body_markdown": str(content.get("body_markdown") or ""),
            "body_html": str(content.get("body_html") or ""),
            "excerpt": summary,
        }
        return JsonResponse(payload)

    ref = (
        ArtifactExternalRef.objects.select_related("artifact")
        .filter(slug_path=slug, artifact__status="published", artifact__type__slug="article")
        .first()
    )
    if ref and (not surface_path or _artifact_matches_surface(ref.artifact, surface_path)):
        artifact = ref.artifact
        revision = _latest_revision(artifact)
        content = (revision.content_json if revision else {}) or {}
        summary = str(content.get("summary") or (artifact.scope_json or {}).get("summary") or "")
        payload = {
            "title": content.get("title") or artifact.title,
            "slug": slug,
            "summary": summary,
            "published_at": artifact.published_at,
            "updated_at": artifact.updated_at,
            "body_markdown": str(content.get("body_markdown") or ""),
            "body_html": str(content.get("body_html") or ""),
            "excerpt": summary,
        }
        return JsonResponse(payload)

    article = get_object_or_404(Article, slug=slug, status="published")
    return JsonResponse(
        {
            "title": article.title,
            "slug": article.slug,
            "summary": article.summary,
            "published_at": article.published_at,
            "updated_at": article.updated_at,
            "body_markdown": "",
            "body_html": article.body,
            "excerpt": article.summary,
        }
    )
