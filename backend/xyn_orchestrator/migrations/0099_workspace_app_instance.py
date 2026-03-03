from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0098_rename_ems_artifact_slug"),
    ]

    operations = [
        migrations.CreateModel(
            name="WorkspaceAppInstance",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("app_slug", models.CharField(max_length=120)),
                ("customer_name", models.CharField(blank=True, max_length=255)),
                ("fqdn", models.CharField(max_length=255)),
                ("deployment_target", models.CharField(choices=[("local", "Local"), ("aws", "AWS")], default="local", max_length=20)),
                ("dns_config_json", models.JSONField(blank=True, default=dict)),
                ("status", models.CharField(choices=[("requested", "Requested"), ("active", "Active"), ("error", "Error")], default="requested", max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "artifact",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="workspace_app_instances", to="xyn_orchestrator.artifact"),
                ),
                (
                    "created_by",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="workspace_app_instances_created", to="auth.user"),
                ),
                (
                    "updated_by",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="workspace_app_instances_updated", to="auth.user"),
                ),
                ("workspace", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="app_instances", to="xyn_orchestrator.workspace")),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="workspaceappinstance",
            constraint=models.UniqueConstraint(fields=("workspace", "app_slug", "fqdn"), name="uniq_workspace_app_instance_fqdn"),
        ),
    ]
