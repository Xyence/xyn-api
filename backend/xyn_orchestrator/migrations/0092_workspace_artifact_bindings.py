from django.db import migrations, models
import django.db.models.deletion
import uuid


def backfill_workspace_artifact_bindings(apps, schema_editor):
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")
    WorkspaceArtifactBinding = apps.get_model("xyn_orchestrator", "WorkspaceArtifactBinding")

    # Strategy: existing Artifact rows are already workspace-scoped (`artifact.workspace_id`),
    # so create one workspace binding per artifact from that source of truth.
    for artifact in Artifact.objects.all().only("id", "workspace_id"):
        WorkspaceArtifactBinding.objects.get_or_create(
            workspace_id=artifact.workspace_id,
            artifact_id=artifact.id,
            defaults={
                "enabled": True,
                "installed_state": "installed",
                "config_ref": None,
            },
        )


def noop(apps, schema_editor):
    return


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0091_backfill_artifact_surfaces"),
    ]

    operations = [
        migrations.CreateModel(
            name="WorkspaceArtifactBinding",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("enabled", models.BooleanField(default=True)),
                ("installed_state", models.CharField(default="installed", max_length=40)),
                ("config_ref", models.CharField(blank=True, max_length=240, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "artifact",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="workspace_bindings", to="xyn_orchestrator.artifact"),
                ),
                (
                    "workspace",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="artifact_bindings", to="xyn_orchestrator.workspace"),
                ),
            ],
            options={"ordering": ["-updated_at", "-created_at"]},
        ),
        migrations.AddConstraint(
            model_name="workspaceartifactbinding",
            constraint=models.UniqueConstraint(fields=("workspace", "artifact"), name="uniq_workspace_artifact_binding"),
        ),
        migrations.RunPython(backfill_workspace_artifact_bindings, noop),
    ]
