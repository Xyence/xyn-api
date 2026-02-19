from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0060_blueprint_lifecycle_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="identityprovider",
            name="fallback_default_role_id",
            field=models.CharField(blank=True, max_length=120, null=True),
        ),
        migrations.AddField(
            model_name="identityprovider",
            name="group_claim_path",
            field=models.CharField(default="groups", max_length=240),
        ),
        migrations.AddField(
            model_name="identityprovider",
            name="group_role_mappings_json",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="identityprovider",
            name="require_group_match",
            field=models.BooleanField(default=False),
        ),
    ]
