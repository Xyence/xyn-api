import uuid

from django.db import migrations, models
import django.db.models.deletion
from django.db.models import Q


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0089_workspace_status"),
    ]

    operations = [
        migrations.CreateModel(
            name="ArtifactSurface",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("key", models.CharField(max_length=120)),
                ("title", models.CharField(max_length=240)),
                ("description", models.TextField(blank=True, default="")),
                (
                    "surface_kind",
                    models.CharField(
                        choices=[
                            ("config", "Config"),
                            ("editor", "Editor"),
                            ("dashboard", "Dashboard"),
                            ("visualizer", "Visualizer"),
                            ("docs", "Docs"),
                        ],
                        default="editor",
                        max_length=20,
                    ),
                ),
                ("route", models.CharField(max_length=280)),
                (
                    "nav_visibility",
                    models.CharField(
                        choices=[("hidden", "Hidden"), ("contextual", "Contextual"), ("always", "Always")],
                        default="hidden",
                        max_length=20,
                    ),
                ),
                ("nav_label", models.CharField(blank=True, default="", max_length=120)),
                ("nav_icon", models.CharField(blank=True, default="", max_length=120)),
                ("nav_group", models.CharField(blank=True, default="", max_length=120)),
                ("renderer", models.JSONField(blank=True, default=dict)),
                ("context", models.JSONField(blank=True, default=dict)),
                ("permissions", models.JSONField(blank=True, default=dict)),
                ("sort_order", models.IntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "artifact",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="surfaces", to="xyn_orchestrator.artifact"),
                ),
            ],
            options={
                "ordering": ["sort_order", "key"],
                "unique_together": {("artifact", "key")},
                "constraints": [
                    models.UniqueConstraint(fields=("route",), condition=~Q(route=""), name="uniq_artifact_surface_route")
                ],
            },
        ),
        migrations.CreateModel(
            name="ArtifactRuntimeRole",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                (
                    "role_kind",
                    models.CharField(
                        choices=[
                            ("route_provider", "Route Provider"),
                            ("job", "Job"),
                            ("event_handler", "Event Handler"),
                            ("integration", "Integration"),
                            ("auth", "Auth"),
                            ("data_model", "Data Model"),
                        ],
                        max_length=40,
                    ),
                ),
                ("spec", models.JSONField(blank=True, default=dict)),
                ("enabled", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "artifact",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="runtime_roles", to="xyn_orchestrator.artifact"),
                ),
            ],
            options={"ordering": ["role_kind", "id"]},
        ),
    ]
