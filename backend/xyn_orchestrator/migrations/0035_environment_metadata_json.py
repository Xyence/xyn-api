from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0034_user_identity_role_binding"),
    ]

    operations = [
        migrations.AddField(
            model_name="environment",
            name="metadata_json",
            field=models.JSONField(blank=True, null=True),
        ),
    ]
