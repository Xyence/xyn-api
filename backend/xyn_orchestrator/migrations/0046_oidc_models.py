from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0045_release_build_state"),
    ]

    operations = [
        migrations.CreateModel(
            name="IdentityProvider",
            fields=[
                ("id", models.CharField(primary_key=True, max_length=120, serialize=False)),
                ("display_name", models.CharField(max_length=200)),
                ("enabled", models.BooleanField(default=True)),
                ("issuer", models.URLField()),
                ("discovery_json", models.JSONField(blank=True, null=True)),
                ("client_id", models.CharField(max_length=240)),
                ("client_secret_ref_json", models.JSONField(blank=True, null=True)),
                ("scopes_json", models.JSONField(blank=True, null=True)),
                ("pkce_enabled", models.BooleanField(default=True)),
                ("prompt", models.CharField(blank=True, max_length=40)),
                ("domain_rules_json", models.JSONField(blank=True, null=True)),
                ("claims_json", models.JSONField(blank=True, null=True)),
                ("audience_rules_json", models.JSONField(blank=True, null=True)),
                ("cached_discovery_doc", models.JSONField(blank=True, null=True)),
                ("cached_jwks", models.JSONField(blank=True, null=True)),
                ("last_discovery_refresh_at", models.DateTimeField(blank=True, null=True)),
                ("jwks_cached_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="identity_providers_created",
                        to="auth.user",
                    ),
                ),
            ],
            options={"ordering": ["id"]},
        ),
        migrations.CreateModel(
            name="AppOIDCClient",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("app_id", models.CharField(max_length=120)),
                ("login_mode", models.CharField(default="redirect", max_length=40)),
                ("allowed_providers_json", models.JSONField(blank=True, null=True)),
                ("redirect_uris_json", models.JSONField(blank=True, null=True)),
                ("post_logout_redirect_uris_json", models.JSONField(blank=True, null=True)),
                ("session_json", models.JSONField(blank=True, null=True)),
                ("token_validation_json", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="oidc_clients_created",
                        to="auth.user",
                    ),
                ),
                (
                    "default_provider",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="default_for_apps",
                        to="xyn_orchestrator.identityprovider",
                    ),
                ),
            ],
            options={"ordering": ["app_id", "-created_at"]},
        ),
        migrations.AddField(
            model_name="useridentity",
            name="provider_id",
            field=models.CharField(blank=True, max_length=120),
        ),
    ]
