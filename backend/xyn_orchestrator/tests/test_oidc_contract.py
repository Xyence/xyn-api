import json
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from authlib.jose import JsonWebKey, jwt

from xyn_orchestrator.models import (
    IdentityProvider,
    AppOIDCClient,
    RoleBinding,
    UserIdentity,
)
from xyn_orchestrator.oidc import get_jwks
from xyn_orchestrator.xyn_api import _decode_oidc_id_token


class OidcContractTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username="staff",
            email="staff@example.com",
            password="pass",
            is_staff=True,
        )
        self.client.force_login(self.user)
        self.identity = UserIdentity.objects.create(
            provider="oidc",
            provider_id="google",
            issuer="https://accounts.google.com",
            subject="staff-subject",
            email="staff@example.com",
            display_name="Staff User",
        )
        RoleBinding.objects.create(
            user_identity=self.identity,
            scope_kind="platform",
            role="platform_admin",
        )
        session = self.client.session
        session["user_identity_id"] = str(self.identity.id)
        session.save()

    def _provider_payload(self):
        return {
            "id": "google-workspace",
            "display_name": "Google Workspace",
            "enabled": True,
            "issuer": "https://accounts.google.com",
            "client": {"client_id": "abc123", "client_secret_ref": {"type": "env", "ref": "OIDC"}},
            "scopes": ["openid", "profile", "email"],
            "pkce": True,
            "domain_rules": {"allowedEmailDomains": ["xyence.io"]},
        }

    def test_provider_crud(self):
        response = self.client.post(
            "/xyn/api/platform/identity-providers",
            data=json.dumps(self._provider_payload()),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        provider_id = response.json().get("id")
        self.assertEqual(provider_id, "google-workspace")
        response = self.client.get(f"/xyn/api/platform/identity-providers/{provider_id}")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["display_name"], "Google Workspace")
        response = self.client.patch(
            f"/xyn/api/platform/identity-providers/{provider_id}",
            data=json.dumps({"display_name": "Google"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        provider = IdentityProvider.objects.get(id=provider_id)
        self.assertEqual(provider.display_name, "Google")

    def test_oidc_config_resolver(self):
        provider = IdentityProvider.objects.create(
            id="google",
            display_name="Google",
            issuer="https://accounts.google.com",
            client_id="abc",
            enabled=True,
        )
        AppOIDCClient.objects.create(
            app_id="xyn-ui",
            login_mode="redirect",
            default_provider=provider,
            allowed_providers_json=["google"],
            redirect_uris_json=["https://xyn.xyence.io/auth/callback"],
        )
        response = self.client.get("/xyn/api/auth/oidc/config?appId=xyn-ui")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["default_provider_id"], "google")
        self.assertEqual(len(payload["allowed_providers"]), 1)

    def test_authorize_redirects_stale_provider_to_default(self):
        provider = IdentityProvider.objects.create(
            id="google",
            display_name="Google",
            issuer="https://accounts.google.com",
            client_id="abc",
            enabled=True,
            discovery_json={"mode": "manual", "authorizationEndpoint": "https://accounts.google.com/o/oauth2/v2/auth"},
        )
        AppOIDCClient.objects.create(
            app_id="ems.platform",
            login_mode="redirect",
            default_provider=provider,
            allowed_providers_json=["google"],
            redirect_uris_json=["https://xyence.io/auth/callback"],
        )
        response = self.client.get(
            "/xyn/api/auth/oidc/g3/authorize",
            {"appId": "ems.platform", "returnTo": "https://ems.xyence.io/auth/callback"},
        )
        self.assertEqual(response.status_code, 302)
        location = response.headers.get("Location", "")
        self.assertIn("/xyn/api/auth/oidc/google/authorize?", location)
        self.assertIn("appId=ems.platform", location)

    def test_oidc_app_client_post_upserts_by_app_id(self):
        provider = IdentityProvider.objects.create(
            id="google",
            display_name="Google",
            issuer="https://accounts.google.com",
            client_id="abc",
            enabled=True,
        )
        old = AppOIDCClient.objects.create(
            app_id="ems.platform",
            login_mode="redirect",
            default_provider=provider,
            allowed_providers_json=["google"],
            redirect_uris_json=["https://old.example.com/auth/callback"],
        )
        newer = AppOIDCClient.objects.create(
            app_id="ems.platform",
            login_mode="redirect",
            default_provider=provider,
            allowed_providers_json=["google"],
            redirect_uris_json=["https://new.example.com/auth/callback"],
        )
        payload = {
            "appId": "ems.platform",
            "loginMode": "redirect",
            "defaultProviderId": "google",
            "allowedProviderIds": ["google"],
            "redirectUris": ["https://xyence.io/auth/callback"],
            "postLogoutRedirectUris": ["https://ems.xyence.io/"],
            "session": {"cookieName": "ems_session", "maxAgeSeconds": 3600},
            "tokenValidation": {"issuerStrict": True, "clockSkewSeconds": 120},
        }
        response = self.client.post(
            "/xyn/api/platform/oidc-app-clients",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AppOIDCClient.objects.filter(app_id="ems.platform").count(), 1)
        kept = AppOIDCClient.objects.get(app_id="ems.platform")
        self.assertEqual(kept.id, newer.id)
        self.assertEqual(kept.redirect_uris_json, ["https://xyence.io/auth/callback"])
        self.assertFalse(AppOIDCClient.objects.filter(id=old.id).exists())

    @mock.patch("xyn_orchestrator.oidc.requests.get")
    def test_provider_test_endpoint(self, mock_get):
        provider = IdentityProvider.objects.create(
            id="google",
            display_name="Google",
            issuer="https://accounts.google.com",
            client_id="abc",
            enabled=True,
        )
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        }
        response = self.client.get(f"/xyn/api/platform/identity-providers/{provider.id}/test")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json().get("ok"))

    @mock.patch("xyn_orchestrator.xyn_api.get_jwks")
    def test_token_validation_audience(self, mock_jwks):
        provider = IdentityProvider.objects.create(
            id="google",
            display_name="Google",
            issuer="https://accounts.google.com",
            client_id="abc",
            enabled=True,
        )
        client = AppOIDCClient.objects.create(
            app_id="xyn-ui",
            login_mode="redirect",
            default_provider=provider,
            allowed_providers_json=["google"],
            redirect_uris_json=["https://xyn.xyence.io/auth/callback"],
        )
        key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        public_key = key.as_dict(is_private=False)
        if not public_key.get("kid"):
            public_key["kid"] = "kid-1"
        jwks = {"keys": [public_key]}
        mock_jwks.return_value = jwks
        header = {"alg": "RS256", "kid": public_key.get("kid")}
        now = int(timezone.now().timestamp())
        claims = {
            "iss": provider.issuer,
            "aud": provider.client_id,
            "sub": "user-1",
            "exp": now + 300,
            "nonce": "nonce-1",
        }
        token = jwt.encode(header, claims, key).decode("utf-8")
        decoded = _decode_oidc_id_token(provider, client, token, "nonce-1")
        self.assertIsNotNone(decoded)
        bad_claims = {**claims, "aud": "other-client"}
        bad_token = jwt.encode(header, bad_claims, key).decode("utf-8")
        decoded_bad = _decode_oidc_id_token(provider, client, bad_token, "nonce-1")
        self.assertIsNone(decoded_bad)

    @mock.patch("xyn_orchestrator.xyn_api._decode_oidc_id_token")
    @mock.patch("xyn_orchestrator.xyn_api.get_discovery_doc")
    @mock.patch("xyn_orchestrator.xyn_api.requests.post")
    def test_domain_allowlist_enforced(self, mock_post, mock_discovery, mock_decode):
        provider = IdentityProvider.objects.create(
            id="google",
            display_name="Google",
            issuer="https://accounts.google.com",
            client_id="abc",
            enabled=True,
            domain_rules_json={"allowedEmailDomains": ["xyence.io"]},
        )
        AppOIDCClient.objects.create(
            app_id="xyn-ui",
            login_mode="redirect",
            default_provider=provider,
            allowed_providers_json=["google"],
            redirect_uris_json=["https://xyn.xyence.io/auth/callback"],
        )
        mock_discovery.return_value = {"token_endpoint": "https://accounts.google.com/token"}
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"id_token": "token"}
        mock_decode.return_value = {
            "sub": "user-1",
            "email": "user@other.com",
            "iss": provider.issuer,
            "aud": provider.client_id,
        }
        session = self.client.session
        session["oidc_state:xyn-ui:google"] = "state-1"
        session["oidc_nonce:xyn-ui:google"] = "nonce-1"
        session["oidc_verifier:xyn-ui:google"] = "verifier"
        session.save()
        response = self.client.get(
            "/xyn/api/auth/oidc/google/callback",
            {"code": "code-1", "state": "state-1", "appId": "xyn-ui"},
        )
        self.assertEqual(response.status_code, 403)

    @mock.patch("xyn_orchestrator.oidc.requests.get")
    def test_jwks_refresh_on_unknown_kid(self, mock_get):
        provider = IdentityProvider.objects.create(
            id="google",
            display_name="Google",
            issuer="https://accounts.google.com",
            client_id="abc",
            enabled=True,
        )
        provider.discovery_json = {"mode": "manual", "jwksUri": "https://jwks.example.com"}
        provider.cached_jwks = {"keys": [{"kid": "old", "kty": "RSA", "n": "a", "e": "AQAB"}]}
        provider.jwks_cached_at = timezone.now()
        provider.save(update_fields=["cached_jwks", "jwks_cached_at", "discovery_json"])
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"keys": [{"kid": "new", "kty": "RSA", "n": "b", "e": "AQAB"}]}
        jwks = get_jwks(provider, kid="new")
        self.assertTrue(any(key.get("kid") == "new" for key in jwks.get("keys", [])))

    def test_public_branding_defaults_and_override_merge(self):
        global_payload = {
            "brand_name": "Xyn Platform",
            "logo_url": "https://cdn.example.com/logo.png",
            "primary_color": "#123456",
            "background_color": "#fafafa",
            "text_color": "#111111",
            "button_radius_px": 10,
        }
        response = self.client.put(
            "/xyn/api/platform/branding",
            data=json.dumps(global_payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.put(
            "/xyn/api/platform/branding/apps/ems.platform",
            data=json.dumps({"display_name": "EMS", "primary_color": "#654321"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        public_response = self.client.get("/xyn/api/public/branding?appId=ems.platform")
        self.assertEqual(public_response.status_code, 200)
        payload = public_response.json()
        self.assertEqual(payload["display_name"], "EMS")
        self.assertEqual(payload["primary_color"], "#654321")
        self.assertEqual(payload["logo_url"], "https://cdn.example.com/logo.png")

    @mock.patch("xyn_orchestrator.xyn_api.get_discovery_doc")
    def test_authorize_blocks_untrusted_return_to(self, mock_discovery):
        provider = IdentityProvider.objects.create(
            id="google",
            display_name="Google",
            issuer="https://accounts.google.com",
            client_id="abc",
            enabled=True,
        )
        AppOIDCClient.objects.create(
            app_id="xyn-ui",
            login_mode="redirect",
            default_provider=provider,
            allowed_providers_json=["google"],
            redirect_uris_json=["https://xyn.xyence.io/auth/callback"],
        )
        mock_discovery.return_value = {"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth"}
        response = self.client.get(
            "/xyn/api/auth/oidc/google/authorize",
            {"appId": "xyn-ui", "returnTo": "https://evil.example.com/phish"},
        )
        self.assertEqual(response.status_code, 302)
        session = self.client.session
        self.assertEqual(session.get("post_login_redirect"), "/app")

    @mock.patch("xyn_orchestrator.xyn_api._decode_oidc_id_token")
    @mock.patch("xyn_orchestrator.xyn_api.requests.post")
    @mock.patch("xyn_orchestrator.xyn_api.get_discovery_doc")
    def test_authorize_callback_preserves_app_and_return_to(self, mock_discovery, mock_post, mock_decode):
        provider = IdentityProvider.objects.create(
            id="google",
            display_name="Google",
            issuer="https://accounts.google.com",
            client_id="abc",
            enabled=True,
        )
        AppOIDCClient.objects.create(
            app_id="ems.platform",
            login_mode="redirect",
            default_provider=provider,
            allowed_providers_json=["google"],
            redirect_uris_json=["https://ems.xyence.io/auth/callback"],
            post_logout_redirect_uris_json=["https://ems.xyence.io/"],
        )
        mock_discovery.side_effect = [
            {"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth"},
            {"token_endpoint": "https://accounts.google.com/token"},
        ]
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"id_token": "token-1"}
        mock_decode.return_value = {
            "sub": "user-1",
            "email": "user@xyence.io",
            "iss": provider.issuer,
            "aud": provider.client_id,
            "name": "User One",
        }
        authorize_response = self.client.get(
            "/xyn/api/auth/oidc/google/authorize",
            {
                "appId": "ems.platform",
                "returnTo": "https://ems.xyence.io/devices",
            },
        )
        self.assertEqual(authorize_response.status_code, 302)
        state = self.client.session.get("oidc_state:ems.platform:google")
        callback_response = self.client.get(
            "/xyn/api/auth/oidc/google/callback",
            {"code": "code-1", "state": state, "appId": "ems.platform"},
        )
        self.assertEqual(callback_response.status_code, 302)
        location = callback_response["Location"]
        self.assertTrue(location.startswith("https://ems.xyence.io") or location.startswith("/"))
        self.assertIn("id_token=token-1", location)

    def test_auth_login_renders_shared_page(self):
        provider = IdentityProvider.objects.create(
            id="google",
            display_name="Google",
            issuer="https://accounts.google.com",
            client_id="abc",
            enabled=True,
        )
        AppOIDCClient.objects.create(
            app_id="xyn-ui",
            login_mode="redirect",
            default_provider=provider,
            allowed_providers_json=["google"],
            redirect_uris_json=["https://xyn.xyence.io/auth/callback"],
        )
        response = self.client.get("/auth/login", {"appId": "xyn-ui", "returnTo": "/app/releases"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Continue with Google")
        self.assertContains(response, "returnTo=/app/releases")
