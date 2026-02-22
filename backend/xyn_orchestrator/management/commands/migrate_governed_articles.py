from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from django.utils.text import slugify

from xyn_orchestrator.models import (
    Article,
    Artifact,
    ArtifactEvent,
    ArtifactExternalRef,
    ArtifactRevision,
    ArtifactType,
    Workspace,
)


ARTICLE_CATEGORIES = {"web", "guide", "core-concepts", "release-note", "internal", "tutorial"}


def _ensure_workspace() -> Workspace:
    workspace = Workspace.objects.filter(slug="platform-builder").first()
    if workspace:
        return workspace
    workspace = Workspace.objects.order_by("created_at").first()
    if workspace:
        return workspace
    return Workspace.objects.create(
        slug="platform-builder",
        name="Platform Builder",
        description="Platform governance and operator documentation",
    )


def _ensure_article_type() -> ArtifactType:
    article_type, _ = ArtifactType.objects.get_or_create(
        slug="article",
        defaults={
            "name": "Article",
            "description": "Governed knowledge artifacts",
            "icon": "BookOpen",
        },
    )
    return article_type


def _derive_guide_category(tags: list[str]) -> str:
    norm = {str(tag).strip().lower() for tag in tags if str(tag).strip()}
    if "core-concepts" in norm:
        return "core-concepts"
    if "tutorial" in norm:
        return "tutorial"
    return "guide"


def _next_unique_slug(workspace_id: str, base_slug: str) -> str:
    base = slugify(base_slug or "")[:240] or "article"
    if not Artifact.objects.filter(workspace_id=workspace_id, slug=base).exists():
        return base
    idx = 2
    while True:
        candidate = slugify(f"{base}-{idx}")[:240] or f"article-{idx}"
        if not Artifact.objects.filter(workspace_id=workspace_id, slug=candidate).exists():
            return candidate
        idx += 1


class Command(BaseCommand):
    help = "Migrate legacy Django articles and legacy doc_page artifacts into governed article artifacts."

    def add_arguments(self, parser):
        parser.add_argument(
            "--keep-legacy-doc-pages-active",
            action="store_true",
            help="Do not deprecate source doc_page artifacts after migration.",
        )

    def handle(self, *args: Any, **options: Any):
        workspace = _ensure_workspace()
        article_type = _ensure_article_type()
        deprecate_legacy_docs = not bool(options.get("keep_legacy_doc_pages_active"))

        migrated_django = 0
        migrated_docs = 0
        normalized = 0

        for legacy in Article.objects.all().order_by("created_at"):
            if ArtifactExternalRef.objects.filter(system="django", external_id=str(legacy.id)).exists():
                continue
            slug = _next_unique_slug(str(workspace.id), legacy.slug or legacy.title)
            status = "published" if legacy.status == "published" else "draft"
            visibility_type = "public" if status == "published" else "private"
            with transaction.atomic():
                artifact = Artifact.objects.create(
                    workspace=workspace,
                    type=article_type,
                    title=legacy.title,
                    slug=slug,
                    status=status,
                    version=1,
                    visibility="public" if status == "published" else "private",
                    published_at=legacy.published_at if status == "published" else None,
                    scope_json={
                        "slug": slug,
                        "category": "web",
                        "visibility_type": visibility_type,
                        "allowed_roles": [],
                        "route_bindings": [],
                        "tags": [],
                        "cover_image_url": "",
                        "canonical_url": f"/articles/{legacy.slug}",
                        "license_json": {},
                    },
                    provenance_json={
                        "source_system": "django",
                        "source_id": str(legacy.id),
                        "original_slug": legacy.slug,
                        "original_url_path": f"/articles/{legacy.slug}",
                    },
                )
                ArtifactRevision.objects.create(
                    artifact=artifact,
                    revision_number=1,
                    content_json={
                        "title": legacy.title,
                        "summary": legacy.summary or "",
                        "body_markdown": "",
                        "body_html": legacy.body or "",
                        "tags": [],
                        "provenance_json": {
                            "source_system": "django",
                            "source_id": str(legacy.id),
                        },
                    },
                    created_by=None,
                )
                ArtifactExternalRef.objects.create(
                    artifact=artifact,
                    system="django",
                    external_id=str(legacy.id),
                    slug_path=legacy.slug or slug,
                )
                ArtifactEvent.objects.create(
                    artifact=artifact,
                    event_type="article_created",
                    actor=None,
                    payload_json={
                        "source_system": "django",
                        "source_id": str(legacy.id),
                        "status": legacy.status,
                    },
                )
                if status == "published":
                    ArtifactEvent.objects.create(
                        artifact=artifact,
                        event_type="article_published",
                        actor=None,
                        payload_json={"source_system": "django", "migrated_at": timezone.now().isoformat()},
                    )
            migrated_django += 1

        doc_pages = Artifact.objects.filter(type__slug="doc_page").order_by("created_at")
        for doc in doc_pages:
            if ArtifactExternalRef.objects.filter(system="doc_page", external_id=str(doc.id)).exists():
                continue
            rev = ArtifactRevision.objects.filter(artifact=doc).order_by("-revision_number").first()
            content = dict((rev.content_json if rev else {}) or {})
            tags = [str(tag).strip().lower() for tag in (content.get("tags") or []) if str(tag).strip()]
            category = _derive_guide_category(tags)
            if category not in ARTICLE_CATEGORIES:
                category = "guide"
            raw_slug = doc.slug or str((doc.scope_json or {}).get("slug") or doc.title)
            slug = _next_unique_slug(str(doc.workspace_id), raw_slug)
            visibility_type = "public" if doc.visibility == "public" else ("private" if doc.visibility == "private" else "authenticated")
            with transaction.atomic():
                article = Artifact.objects.create(
                    workspace=doc.workspace,
                    type=article_type,
                    title=doc.title,
                    slug=slug,
                    status=doc.status if doc.status in {"draft", "reviewed", "ratified", "published", "deprecated"} else "draft",
                    version=1,
                    visibility=doc.visibility,
                    author=doc.author,
                    custodian=doc.custodian,
                    ratified_by=doc.ratified_by,
                    ratified_at=doc.ratified_at,
                    published_at=doc.published_at,
                    scope_json={
                        "slug": slug,
                        "category": category,
                        "visibility_type": visibility_type,
                        "allowed_roles": [],
                        "route_bindings": (doc.scope_json or {}).get("route_bindings") or [],
                        "tags": tags,
                        "cover_image_url": "",
                        "canonical_url": "",
                        "license_json": {},
                    },
                    provenance_json={
                        "source_system": "doc_page",
                        "source_id": str(doc.id),
                    },
                )
                ArtifactRevision.objects.create(
                    artifact=article,
                    revision_number=1,
                    content_json={
                        "title": doc.title,
                        "summary": str(content.get("summary") or ""),
                        "body_markdown": str(content.get("body_markdown") or ""),
                        "body_html": str(content.get("body_html") or ""),
                        "tags": tags,
                        "provenance_json": {"source_system": "doc_page", "source_id": str(doc.id)},
                    },
                    created_by=rev.created_by if rev else None,
                )
                ArtifactExternalRef.objects.create(
                    artifact=article,
                    system="doc_page",
                    external_id=str(doc.id),
                    slug_path=doc.slug or slug,
                )
                ArtifactEvent.objects.create(
                    artifact=article,
                    event_type="article_created",
                    actor=None,
                    payload_json={"source_system": "doc_page", "source_id": str(doc.id)},
                )
                if deprecate_legacy_docs and doc.status != "deprecated":
                    doc.status = "deprecated"
                    doc.save(update_fields=["status", "updated_at"])
            migrated_docs += 1

        # Normalize guide taxonomy and deprecate walkthrough duplicates.
        candidate_guides = Artifact.objects.filter(type__slug="article")
        for article in candidate_guides:
            scope = dict(article.scope_json or {})
            slug = str(article.slug or scope.get("slug") or "").strip().lower()
            title = str(article.title or "").strip().lower()
            category = str(scope.get("category") or "").strip().lower()
            updated = False

            if (slug == "core-concepts" or category == "core-concepts" or title == "core concepts") and category != "guide":
                scope["category"] = "guide"
                tags = [str(tag).strip().lower() for tag in (scope.get("tags") or []) if str(tag).strip()]
                if "core-concepts" not in tags:
                    tags.append("core-concepts")
                scope["tags"] = tags
                updated = True

            if slug == "subscriber-notes" or title == "subscriber notes walkthrough":
                if article.status != "deprecated":
                    article.status = "deprecated"
                    updated = True

            if updated:
                article.scope_json = scope
                article.save(update_fields=["scope_json", "status", "updated_at"])
                normalized += 1

        self.stdout.write(
            self.style.SUCCESS(
                "Governed article migration complete. "
                f"migrated_django={migrated_django}, migrated_doc_pages={migrated_docs}, normalized={normalized}"
            )
        )
