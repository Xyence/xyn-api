import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0018_alter_blueprintdraftsession_status_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Registry",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200)),
                (
                    "registry_type",
                    models.CharField(
                        choices=[
                            ("module", "Module"),
                            ("bundle", "Bundle"),
                            ("blueprint", "Blueprint"),
                            ("release", "Release"),
                        ],
                        max_length=20,
                    ),
                ),
                ("description", models.TextField(blank=True)),
                ("url", models.URLField(blank=True)),
                (
                    "status",
                    models.CharField(
                        choices=[("active", "Active"), ("inactive", "Inactive"), ("error", "Error")],
                        default="active",
                        max_length=20,
                    ),
                ),
                ("last_sync_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="registries_created",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="registries_updated",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="Run",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                (
                    "entity_type",
                    models.CharField(
                        choices=[
                            ("blueprint", "Blueprint"),
                            ("registry", "Registry"),
                            ("module", "Module"),
                            ("release_plan", "Release plan"),
                        ],
                        max_length=30,
                    ),
                ),
                ("entity_id", models.UUIDField()),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("running", "Running"),
                            ("succeeded", "Succeeded"),
                            ("failed", "Failed"),
                        ],
                        default="pending",
                        max_length=20,
                    ),
                ),
                ("summary", models.CharField(blank=True, max_length=240)),
                ("log_text", models.TextField(blank=True)),
                ("error", models.TextField(blank=True)),
                ("metadata_json", models.JSONField(blank=True, null=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="runs_created",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="RunArtifact",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200)),
                ("kind", models.CharField(blank=True, max_length=100)),
                ("url", models.TextField(blank=True)),
                ("metadata_json", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "run",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="artifacts", to="xyn_orchestrator.run"),
                ),
            ],
            options={
                "ordering": ["created_at"],
            },
        ),
    ]
