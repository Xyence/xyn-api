from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0073_article_categories_and_publish_bindings"),
    ]

    operations = [
        migrations.CreateModel(
            name="VideoRender",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("provider", models.CharField(default="unknown", max_length=80)),
                (
                    "status",
                    models.CharField(
                        choices=[("queued", "Queued"), ("running", "Running"), ("succeeded", "Succeeded"), ("failed", "Failed"), ("canceled", "Canceled")],
                        default="queued",
                        max_length=20,
                    ),
                ),
                ("requested_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("request_payload_json", models.JSONField(blank=True, default=dict)),
                ("result_payload_json", models.JSONField(blank=True, default=dict)),
                ("output_assets", models.JSONField(blank=True, default=list)),
                ("error_message", models.TextField(blank=True)),
                ("error_details_json", models.JSONField(blank=True, null=True)),
                (
                    "article",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="video_renders", to="xyn_orchestrator.artifact"),
                ),
            ],
            options={"ordering": ["-requested_at"]},
        ),
        migrations.AddField(
            model_name="artifact",
            name="format",
            field=models.CharField(
                choices=[("standard", "Standard"), ("video_explainer", "Video Explainer")],
                default="standard",
                max_length=30,
            ),
        ),
        migrations.AddField(
            model_name="artifact",
            name="video_spec_json",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="artifact",
            name="video_latest_render",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="+",
                to="xyn_orchestrator.videorender",
            ),
        ),
    ]
