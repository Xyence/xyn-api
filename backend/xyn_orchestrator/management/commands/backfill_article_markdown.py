from __future__ import annotations

from django.core.management.base import BaseCommand
from django.db import transaction

from markdownify import markdownify as markdownify_html

from xyn_orchestrator.models import Artifact, ArtifactEvent, ArtifactRevision, Workspace


def _convert_html_to_markdown(value: str) -> str:
    source = str(value or "").strip()
    if not source:
        return ""
    return str(markdownify_html(source, heading_style="ATX", bullets="-") or "").strip()


class Command(BaseCommand):
    help = "Backfill article body_markdown from body_html when markdown is missing."

    def add_arguments(self, parser):
        parser.add_argument("--workspace-slug", dest="workspace_slug", default="", help="Optional workspace slug filter.")
        parser.add_argument("--dry-run", action="store_true", help="Show changes without writing revisions.")

    def handle(self, *args, **options):
        workspace_slug = str(options.get("workspace_slug") or "").strip()
        dry_run = bool(options.get("dry_run"))
        qs = Artifact.objects.filter(type__slug="article").select_related("workspace")
        if workspace_slug:
            workspace = Workspace.objects.filter(slug=workspace_slug).first()
            if not workspace:
                self.stdout.write(self.style.ERROR(f"Workspace not found: {workspace_slug}"))
                return
            qs = qs.filter(workspace=workspace)

        converted_count = 0
        skipped_count = 0
        for artifact in qs.order_by("created_at"):
            latest = artifact.revisions.order_by("-revision_number").first()
            if not latest:
                skipped_count += 1
                continue
            content = dict((latest.content_json if latest else {}) or {})
            body_markdown = str(content.get("body_markdown") or "").strip()
            body_html = str(content.get("body_html") or "").strip()
            if body_markdown or not body_html:
                skipped_count += 1
                continue
            converted = _convert_html_to_markdown(body_html)
            if not converted:
                skipped_count += 1
                continue
            converted_count += 1
            if dry_run:
                self.stdout.write(f"[dry-run] {artifact.id} slug={artifact.slug} workspace={artifact.workspace.slug}")
                continue
            content["body_markdown"] = converted
            provenance = dict(content.get("provenance_json") or {})
            provenance["html_to_markdown"] = {"source": "backfill_article_markdown"}
            content["provenance_json"] = provenance
            with transaction.atomic():
                revision_no = int(artifact.version or 0) + 1
                ArtifactRevision.objects.create(
                    artifact=artifact,
                    revision_number=revision_no,
                    content_json=content,
                    created_by=None,
                )
                artifact.version = revision_no
                artifact.save(update_fields=["version", "updated_at"])
                ArtifactEvent.objects.create(
                    artifact=artifact,
                    event_type="article_revision_created",
                    actor=None,
                    payload_json={"revision_number": revision_no, "source": "html_to_markdown_backfill"},
                )
                self.stdout.write(f"[converted] {artifact.id} slug={artifact.slug} workspace={artifact.workspace.slug}")

        self.stdout.write(
            self.style.SUCCESS(
                f"Backfill complete. converted={converted_count} skipped={skipped_count} dry_run={dry_run}"
            )
        )
