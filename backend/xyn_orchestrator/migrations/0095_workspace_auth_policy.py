from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0094_workspace_lifecycle_metadata"),
    ]

    operations = [
        migrations.AddField(
            model_name="workspace",
            name="auth_mode",
            field=models.CharField(default="local", max_length=20),
        ),
        migrations.AddField(
            model_name="workspace",
            name="oidc_config_ref",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]
