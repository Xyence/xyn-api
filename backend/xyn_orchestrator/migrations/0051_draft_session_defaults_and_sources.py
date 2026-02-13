from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0050_reports_and_platform_config"),
    ]

    operations = [
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="draft_kind",
            field=models.CharField(
                choices=[("blueprint", "Blueprint"), ("solution", "Solution")],
                default="blueprint",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="has_generated_output",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="initial_prompt",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="namespace",
            field=models.CharField(blank=True, max_length=120),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="project_key",
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="revision_instruction",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="selected_context_pack_ids",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="source_artifacts",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="submitted_payload_json",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="title",
            field=models.CharField(blank=True, max_length=200),
        ),
    ]
