from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0095_workspace_auth_policy"),
    ]

    operations = [
        migrations.AddField(
            model_name="workspace",
            name="oidc_allow_auto_provision",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="workspace",
            name="oidc_allowed_email_domains_json",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="workspace",
            name="oidc_claim_email",
            field=models.CharField(default="email", max_length=120),
        ),
        migrations.AddField(
            model_name="workspace",
            name="oidc_client_id",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="workspace",
            name="oidc_client_secret_ref",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="workspace_oidc_policies",
                to="xyn_orchestrator.secretref",
            ),
        ),
        migrations.AddField(
            model_name="workspace",
            name="oidc_enabled",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="workspace",
            name="oidc_issuer_url",
            field=models.URLField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="workspace",
            name="oidc_scopes",
            field=models.CharField(default="openid profile email", max_length=255),
        ),
    ]
