from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0078_seed_packs"),
    ]

    operations = [
        migrations.AlterField(
            model_name="artifact",
            name="format",
            field=models.CharField(
                choices=[
                    ("standard", "Standard"),
                    ("video_explainer", "Video Explainer"),
                    ("workflow", "Workflow"),
                ],
                default="standard",
                max_length=30,
            ),
        ),
        migrations.AddField(
            model_name="artifact",
            name="workflow_profile",
            field=models.CharField(blank=True, default="", max_length=40),
        ),
        migrations.AddField(
            model_name="artifact",
            name="workflow_spec_json",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="artifact",
            name="workflow_state_schema_version",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name="WorkflowRun",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("status", models.CharField(choices=[("running", "Running"), ("completed", "Completed"), ("failed", "Failed"), ("aborted", "Aborted")], default="running", max_length=20)),
                ("started_at", models.DateTimeField(auto_now_add=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("metadata_json", models.JSONField(blank=True, default=dict)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="workflow_runs",
                        to="xyn_orchestrator.useridentity",
                    ),
                ),
                (
                    "workflow_artifact",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="workflow_runs", to="xyn_orchestrator.artifact"),
                ),
            ],
            options={"ordering": ["-started_at"]},
        ),
        migrations.CreateModel(
            name="WorkflowRunEvent",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("step_id", models.CharField(blank=True, max_length=120)),
                ("event_type", models.CharField(max_length=80)),
                ("payload_json", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "run",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="events", to="xyn_orchestrator.workflowrun"),
                ),
            ],
            options={"ordering": ["created_at"]},
        ),
    ]
