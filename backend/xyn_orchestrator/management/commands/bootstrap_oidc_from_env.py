import json
import os
from django.core.management.base import BaseCommand

from xyn_orchestrator.models import IdentityProvider, AppOIDCClient


class Command(BaseCommand):
    help = "Bootstrap OIDC configuration from legacy env vars."

    def handle(self, *args, **options):
        issuer = "https://accounts.google.com"
        client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
        client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
        secret_ref_raw = os.environ.get("GOOGLE_CLIENT_SECRET_REF", "").strip()
        redirect_uri = os.environ.get("OIDC_REDIRECT_URI", "").strip()
        redirect_uris = os.environ.get("OIDC_REDIRECT_URIS", "").strip()
        scopes = os.environ.get("OIDC_SCOPES", "openid profile email").strip()
        allowed_domains = [
            domain.strip()
            for domain in os.environ.get("OIDC_ALLOWED_DOMAINS", "").split(",")
            if domain.strip()
        ]

        if not client_id:
            self.stdout.write("Missing GOOGLE_CLIENT_ID; nothing to bootstrap.")
            return

        provider_id = "google-workspace"
        secret_ref = None
        if secret_ref_raw:
            try:
                secret_ref = json.loads(secret_ref_raw)
            except json.JSONDecodeError:
                secret_ref = {"type": "aws.secrets_manager", "ref": secret_ref_raw}
        elif client_secret:
            secret_ref = {"type": "env", "ref": "GOOGLE_CLIENT_SECRET"}
        provider, created = IdentityProvider.objects.get_or_create(
            id=provider_id,
            defaults={
                "display_name": os.environ.get("OIDC_PROVIDER_NAME", "Google Workspace"),
                "enabled": True,
                "issuer": issuer,
                "client_id": client_id,
                "client_secret_ref_json": secret_ref,
                "scopes_json": scopes.split(),
                "pkce_enabled": True,
                "domain_rules_json": {"allowedEmailDomains": allowed_domains},
                "claims_json": {
                    "subject": "sub",
                    "email": "email",
                    "emailVerified": "email_verified",
                    "name": "name",
                    "givenName": "given_name",
                    "familyName": "family_name",
                    "picture": "picture",
                },
                "audience_rules_json": {"acceptAudiences": [client_id], "acceptAzp": True},
            },
        )
        if not created:
            provider.issuer = issuer
            provider.client_id = client_id
            provider.scopes_json = scopes.split()
            provider.domain_rules_json = {"allowedEmailDomains": allowed_domains}
            if secret_ref:
                provider.client_secret_ref_json = secret_ref
            provider.save(update_fields=[
                "issuer",
                "client_id",
                "scopes_json",
                "domain_rules_json",
                "client_secret_ref_json",
                "updated_at",
            ])

        app_id = os.environ.get("OIDC_APP_ID", "xyn-ui").strip() or "xyn-ui"
        redirect_uri_list = []
        if redirect_uris:
            redirect_uri_list = [item.strip() for item in redirect_uris.split(",") if item.strip()]
        elif redirect_uri:
            redirect_uri_list = [redirect_uri]
        if not redirect_uri_list:
            self.stdout.write("OIDC_REDIRECT_URI(S) missing; app client will be created without redirect URI.")
        client, created = AppOIDCClient.objects.get_or_create(
            app_id=app_id,
            defaults={
                "login_mode": "redirect",
                "default_provider": provider,
                "allowed_providers_json": [provider.id],
                "redirect_uris_json": redirect_uri_list,
                "post_logout_redirect_uris_json": [],
                "session_json": {"cookieName": "xyn_session", "maxAgeSeconds": 28800},
                "token_validation_json": {"issuerStrict": True, "clockSkewSeconds": 120},
            },
        )
        if not created:
            client.default_provider = provider
            client.allowed_providers_json = list(set((client.allowed_providers_json or []) + [provider.id]))
            for uri in redirect_uri_list:
                if uri not in (client.redirect_uris_json or []):
                    client.redirect_uris_json = (client.redirect_uris_json or []) + [uri]
            client.save(update_fields=[
                "default_provider",
                "allowed_providers_json",
                "redirect_uris_json",
                "updated_at",
            ])

        self.stdout.write(f"Bootstrapped provider {provider.id} and app client {client.app_id}.")
