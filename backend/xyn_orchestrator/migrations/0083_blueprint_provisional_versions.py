import django.db.models.deletion
from django.db import migrations, models
from django.db.models import Q


def forward_backfill(apps, schema_editor):
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")
    Blueprint = apps.get_model("xyn_orchestrator", "Blueprint")

    for artifact in Artifact.objects.select_related("type").filter(type__slug="blueprint").order_by("created_at"):
        family_id = (artifact.family_id or "").strip()
        if not family_id:
            family_id = str(artifact.id)
        updates = []
        if artifact.family_id != family_id:
            artifact.family_id = family_id
            updates.append("family_id")
        if updates:
            artifact.save(update_fields=[*updates, "updated_at"])

    for blueprint in Blueprint.objects.select_related("artifact").all().order_by("created_at"):
        if blueprint.artifact_id:
            family_id = (blueprint.artifact.family_id or "").strip() or str(blueprint.artifact_id)
            updates = []
            if blueprint.blueprint_family_id != family_id:
                blueprint.blueprint_family_id = family_id
                updates.append("blueprint_family_id")
            parent_id = blueprint.artifact.parent_artifact_id
            if parent_id and blueprint.derived_from_artifact_id != parent_id:
                blueprint.derived_from_artifact_id = parent_id
                updates.append("derived_from_artifact")
            if updates:
                blueprint.save(update_fields=[*updates, "updated_at"])
        elif not (blueprint.blueprint_family_id or "").strip():
            blueprint.blueprint_family_id = str(blueprint.id)
            blueprint.save(update_fields=["blueprint_family_id", "updated_at"])


def reverse_backfill(apps, schema_editor):
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")
    Blueprint = apps.get_model("xyn_orchestrator", "Blueprint")
    Artifact.objects.filter(type__slug="blueprint").update(family_id="")
    Blueprint.objects.update(blueprint_family_id="", derived_from_artifact=None)


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0082_ledgerevent"),
    ]

    operations = [
        migrations.AddField(
            model_name="artifact",
            name="family_id",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.AddField(
            model_name="blueprint",
            name="blueprint_family_id",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.AddField(
            model_name="blueprint",
            name="derived_from_artifact",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="derived_blueprints",
                to="xyn_orchestrator.artifact",
            ),
        ),
        migrations.RunPython(forward_backfill, reverse_backfill),
        migrations.AddConstraint(
            model_name="artifact",
            constraint=models.UniqueConstraint(
                fields=("family_id", "artifact_state"),
                condition=(~Q(family_id="") & Q(artifact_state="canonical")),
                name="uniq_artifact_canonical_per_family",
            ),
        ),
    ]
