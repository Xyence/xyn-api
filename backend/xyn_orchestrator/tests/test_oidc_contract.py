import json
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from authlib.jose import JsonWebKey, jwt

from xyn_orchestrator.models import IdentityProvider, AppOIDCClient
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
