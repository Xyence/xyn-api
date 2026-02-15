from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0056_draftsessionrevision_snapshot_action"),
    ]

    operations = [
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="metadata_json",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]

