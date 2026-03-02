from django.db import migrations, models
import django.db.models.deletion


def backfill_workspace_org_name(apps, schema_editor):
    Workspace = apps.get_model("xyn_orchestrator", "Workspace")
    for workspace in Workspace.objects.filter(org_name__isnull=True).only("id", "name", "org_name"):
        workspace.org_name = str(workspace.name or "").strip() or None
        workspace.save(update_fields=["org_name", "updated_at"])


def noop(apps, schema_editor):
    return


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0093_seed_demo_artifacts"),
    ]

    operations = [
        migrations.AddField(
            model_name="workspace",
            name="kind",
            field=models.CharField(default="customer", max_length=64),
        ),
        migrations.AddField(
            model_name="workspace",
            name="lifecycle_stage",
            field=models.CharField(default="prospect", max_length=64),
        ),
        migrations.AddField(
            model_name="workspace",
            name="metadata_json",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="workspace",
            name="org_name",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name="workspace",
            name="parent_workspace",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="children", to="xyn_orchestrator.workspace"),
        ),
        migrations.RunPython(backfill_workspace_org_name, noop),
    ]
