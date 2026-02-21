from django.db import migrations, models
import django.db.models.deletion


def _migrate_auth_type_to_api_key(apps, schema_editor):
    ProviderCredential = apps.get_model("xyn_orchestrator", "ProviderCredential")
    ProviderCredential.objects.filter(auth_type="api_key_encrypted").update(auth_type="api_key")


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0068_providercredential_agentdefinition_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="providercredential",
            name="auth_type",
            field=models.CharField(
                choices=[("api_key", "API key"), ("env_ref", "Environment variable")],
                default="api_key",
                max_length=40,
            ),
        ),
        migrations.AddField(
            model_name="providercredential",
            name="secret_ref",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="provider_credentials",
                to="xyn_orchestrator.secretref",
            ),
        ),
        migrations.RunPython(_migrate_auth_type_to_api_key, migrations.RunPython.noop),
    ]
