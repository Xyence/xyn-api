from django.db import migrations, models


def _backfill_outcome(apps, schema_editor):
    VideoRender = apps.get_model("xyn_orchestrator", "VideoRender")
    for row in VideoRender.objects.all().iterator():
        current_outcome = str(getattr(row, "outcome", "") or "").strip().lower()
        if current_outcome:
            continue
        output_assets = row.output_assets if isinstance(row.output_assets, list) else []
        result_payload = row.result_payload_json if isinstance(row.result_payload_json, dict) else {}
        error_message = str(row.error_message or "")
        filtered_markers = [
            "raimediafiltered",
            "policy-filtered",
            "blocked by provider policy",
        ]
        combined = f"{error_message} {result_payload}".lower()
        has_video = any(str((asset or {}).get("type") or "").strip().lower() == "video" for asset in output_assets)
        if row.status == "canceled":
            row.outcome = "canceled"
        elif has_video:
            row.outcome = "success"
        elif any(marker in combined for marker in filtered_markers):
            row.outcome = "filtered"
        elif row.status == "failed":
            row.outcome = "failed"
        elif row.status == "succeeded":
            row.outcome = "success"
        else:
            row.outcome = "failed"
        row.save(update_fields=["outcome"])


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0087_artifact_packages_and_bindings"),
    ]

    operations = [
        migrations.AddField(
            model_name="videorender",
            name="outcome",
            field=models.CharField(
                blank=True,
                choices=[
                    ("success", "Success"),
                    ("failed", "Failed"),
                    ("filtered", "Filtered"),
                    ("canceled", "Canceled"),
                    ("timeout", "Timeout"),
                ],
                default="",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="videorender",
            name="provider_operation_name",
            field=models.CharField(blank=True, default="", max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="videorender",
            name="provider_operation_id",
            field=models.CharField(blank=True, default="", max_length=120),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="videorender",
            name="provider_filtered_count",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="videorender",
            name="provider_filtered_reasons",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="videorender",
            name="provider_error_code",
            field=models.CharField(blank=True, default="", max_length=80),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="videorender",
            name="provider_error_message",
            field=models.TextField(blank=True, default=""),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="videorender",
            name="provider_response_excerpt",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="videorender",
            name="last_provider_status_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="videorender",
            name="export_package_generated",
            field=models.BooleanField(default=False),
        ),
        migrations.RunPython(_backfill_outcome, migrations.RunPython.noop),
    ]
