import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("articles", "0021_run_context_fields"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name="run",
            name="entity_type",
            field=models.CharField(
                choices=[
                    ("blueprint", "Blueprint"),
                    ("registry", "Registry"),
                    ("module", "Module"),
                    ("release_plan", "Release plan"),
                    ("dev_task", "Dev task"),
                ],
                max_length=30,
            ),
        ),
        migrations.CreateModel(
            name="DevTask",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("title", models.CharField(max_length=240)),
                (
                    "task_type",
                    models.CharField(
                        choices=[
                            ("codegen", "Codegen"),
                            ("module_scaffold", "Module scaffold"),
                            ("release_plan_generate", "Release plan generate"),
                            ("registry_sync", "Registry sync"),
                            ("deploy", "Deploy"),
                        ],
                        max_length=40,
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
                            ("canceled", "Canceled"),
                        ],
                        default="queued",
                        max_length=20,
                    ),
                ),
                ("priority", models.IntegerField(default=0)),
                ("attempts", models.PositiveIntegerField(default=0)),
                ("max_attempts", models.PositiveIntegerField(default=3)),
                ("locked_by", models.CharField(blank=True, max_length=120)),
                ("locked_at", models.DateTimeField(blank=True, null=True)),
                ("source_entity_type", models.CharField(max_length=60)),
                ("source_entity_id", models.UUIDField()),
                ("input_artifact_key", models.CharField(blank=True, max_length=200)),
                ("last_error", models.TextField(blank=True)),
                ("context_purpose", models.CharField(default="any", max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "context_packs",
                    models.ManyToManyField(blank=True, related_name="dev_tasks", to="articles.contextpack"),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="dev_tasks_created",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="dev_tasks_updated",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "source_run",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="dev_tasks_source",
                        to="articles.run",
                    ),
                ),
                (
                    "result_run",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="dev_tasks_result",
                        to="articles.run",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
    ]
