from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0054_release_target_auto_generated"),
    ]

    operations = [
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="context_resolved_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]

