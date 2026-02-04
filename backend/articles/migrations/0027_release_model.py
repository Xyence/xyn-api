import uuid

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0026_release_plan_deployment"),
    ]

    operations = [
        migrations.CreateModel(
            name="Release",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)),
                ("version", models.CharField(max_length=64)),
                ("status", models.CharField(max_length=20, default="draft")),
                ("artifacts_json", models.JSONField(null=True, blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "blueprint",
                    models.ForeignKey(
                        null=True,
                        blank=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="releases",
                        to="articles.blueprint",
                    ),
                ),
                (
                    "release_plan",
                    models.ForeignKey(
                        null=True,
                        blank=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="releases",
                        to="articles.releaseplan",
                    ),
                ),
                (
                    "created_from_run",
                    models.ForeignKey(
                        null=True,
                        blank=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="releases",
                        to="articles.run",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        null=True,
                        blank=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="releases_created",
                        to="auth.user",
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        null=True,
                        blank=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="releases_updated",
                        to="auth.user",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
