from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0083_blueprint_provisional_versions"),
    ]

    operations = [
        migrations.AddField(
            model_name="artifact",
            name="content_hash",
            field=models.CharField(blank=True, default="", max_length=128),
        ),
        migrations.AddField(
            model_name="artifact",
            name="validation_errors_json",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="artifact",
            name="validation_status",
            field=models.CharField(
                choices=[("pass", "Pass"), ("fail", "Fail"), ("warning", "Warning"), ("unknown", "Unknown")],
                default="unknown",
                max_length=20,
            ),
        ),
    ]
