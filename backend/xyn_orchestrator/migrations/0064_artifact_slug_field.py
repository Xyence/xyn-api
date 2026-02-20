from django.db import migrations, models
from django.db.models import Q
from django.utils.text import slugify


def _backfill_artifact_slugs(apps, schema_editor):
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")
    ArtifactExternalRef = apps.get_model("xyn_orchestrator", "ArtifactExternalRef")
    used_by_workspace = {}

    artifacts = Artifact.objects.all().order_by("workspace_id", "created_at", "id")
    for artifact in artifacts.iterator():
        workspace_key = str(artifact.workspace_id)
        used = used_by_workspace.setdefault(workspace_key, set())

        scope = artifact.scope_json if isinstance(artifact.scope_json, dict) else {}
        candidate = str(scope.get("slug") or "").strip()
        if not candidate:
            ref = (
                ArtifactExternalRef.objects.filter(artifact_id=artifact.id)
                .exclude(slug_path="")
                .order_by("created_at")
                .first()
            )
            candidate = str(ref.slug_path if ref else "").strip()
        if not candidate:
            candidate = str(artifact.title or "").strip()

        base_slug = slugify(candidate).strip().lower()
        if not base_slug:
            base_slug = slugify(str(artifact.id)).strip().lower()
        if not base_slug:
            continue

        next_slug = base_slug
        suffix = 2
        while next_slug in used:
            suffix_text = f"-{suffix}"
            trim = max(1, 240 - len(suffix_text))
            next_slug = f"{base_slug[:trim]}{suffix_text}"
            suffix += 1

        artifact.slug = next_slug
        artifact.save(update_fields=["slug"])
        used.add(next_slug)


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0063_seed_workspaces_and_migrate_articles"),
    ]

    operations = [
        migrations.AddField(
            model_name="artifact",
            name="slug",
            field=models.SlugField(blank=True, default="", max_length=240),
        ),
        migrations.RunPython(_backfill_artifact_slugs, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="artifact",
            constraint=models.UniqueConstraint(
                condition=~Q(slug=""),
                fields=("workspace", "slug"),
                name="uniq_artifact_workspace_slug",
            ),
        ),
    ]
