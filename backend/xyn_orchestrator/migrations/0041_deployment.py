from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0040_instance_runtime"),
    ]

    operations = [
        migrations.CreateModel(
            name="Deployment",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("idempotency_key", models.CharField(max_length=64, unique=True)),
                ("idempotency_base", models.CharField(db_index=True, max_length=64)),
                (
                    "deploy_kind",
                    models.CharField(
                        choices=[("release", "Release"), ("release_plan", "Release plan")],
                        default="release",
                        max_length=20,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("running", "Running"),
                            ("succeeded", "Succeeded"),
                            ("failed", "Failed"),
                        ],
                        default="queued",
                        max_length=20,
                    ),
                ),
                ("submitted_by", models.CharField(blank=True, max_length=120)),
                ("transport", models.CharField(default="ssm", max_length=40)),
                ("transport_ref", models.JSONField(blank=True, null=True)),
                ("stdout_excerpt", models.TextField(blank=True)),
                ("stderr_excerpt", models.TextField(blank=True)),
                ("error_message", models.TextField(blank=True)),
                ("artifacts_json", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "instance",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="deployment_records",
                        to="xyn_orchestrator.provisionedinstance",
                    ),
                ),
                (
                    "release",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="deployments",
                        to="xyn_orchestrator.release",
                    ),
                ),
                (
                    "release_plan",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="deployment_records",
                        to="xyn_orchestrator.releaseplan",
                    ),
                ),
                (
                    "run",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="deployments",
                        to="xyn_orchestrator.run",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
    ]
