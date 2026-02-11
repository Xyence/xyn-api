import json
import os
import sys
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from unittest import mock

from django.test import TestCase, RequestFactory
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import JsonResponse
from jsonschema import Draft202012Validator
import yaml

from xyn_orchestrator.blueprints import (
    _build_module_catalog,
    _build_run_history_summary,
    _generate_implementation_plan,
    _release_target_payload,
    _select_context_packs_for_dev_task,
    _select_next_slice,
    internal_release_resolve,
    internal_release_upsert,
    internal_release_target_current_release,
    internal_release_target_check_drift,
    internal_releases_latest,
    internal_release_target_deploy_latest,
    internal_release_target_rollback_last_success,
    internal_releases_retention_report,
    internal_releases_gc,
    internal_artifacts_gc,
    internal_release_target_deploy_manifest,
    internal_release_promote,
    _write_run_artifact,
)
from xyn_orchestrator.xyn_api import _validate_release_target_payload
from xyn_orchestrator import xyn_api as xyn_api_module
from xyn_orchestrator.worker_tasks import (
    _apply_scaffold_for_work_item,
    _collect_git_diff,
    _build_deploy_manifest,
    _build_deploy_state_metadata,
    _build_remote_pull_apply_commands,
    _build_ssm_service_digest_commands,
    _parse_service_digest_lines,
    _merge_release_env,
    _mark_noop_codegen,
    _redact_secrets,
    _stage_all,
    _normalize_sha256,
    _normalize_digest,
    _validate_release_manifest_pinned,
    _route53_ensure_with_noop,
    _run_remote_deploy,
    _work_item_capabilities,
)
from xyn_orchestrator.models import (
    Blueprint,
    ContextPack,
    DevTask,
    Environment,
    ProvisionedInstance,
    Release,
    ReleaseTarget,
    RoleBinding,
    Run,
    UserIdentity,
    Tenant,
    TenantMembership,
    BrandProfile,
    Device,
)


class OIDCAuthTests(TestCase):
    def _make_env(self):
        return Environment.objects.create(
            name="Dev",
            slug="dev",
            metadata_json={
                "oidc": {
                    "issuer_url": "https://issuer.example.com",
                    "client_id": "client-123",
                    "client_secret_ref": {"ref": "ssm:/oidc/secret"},
                    "redirect_uri": "https://xyence.io/auth/callback",
                    "scopes": "openid profile email",
                    "allowed_email_domains": ["xyence.io"],
                }
            },
        )

    def _mock_token_post(self, *args, **kwargs):
        class FakeResponse:
            status_code = 200

            def json(self_inner):
                return {"id_token": "token-abc"}

        return FakeResponse()

    def test_oidc_login_redirect_sets_state_nonce(self):
        env = self._make_env()
        with mock.patch.object(xyn_api_module, "_get_oidc_config") as get_config:
            get_config.return_value = {"authorization_endpoint": "https://issuer.example.com/auth"}
            response = self.client.get(f"/auth/login?environment_id={env.id}")
        self.assertEqual(response.status_code, 302)
        session = self.client.session
        self.assertIn("oidc_state", session)
        self.assertIn("oidc_nonce", session)

    def test_oidc_callback_upserts_identity_and_session(self):
        env = self._make_env()
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="sub-123",
        )
        RoleBinding.objects.create(user_identity=identity, scope_kind="platform", role="platform_admin")
        session = self.client.session
        session["oidc_state"] = "state-123"
        session["oidc_nonce"] = "nonce-123"
        session["environment_id"] = str(env.id)
        session["post_login_redirect"] = "/app/ems"
        session.save()
        with (
            mock.patch.object(xyn_api_module, "_get_oidc_config") as get_config,
            mock.patch.object(xyn_api_module, "_resolve_secret_ref") as resolve_secret,
            mock.patch.object(xyn_api_module, "_decode_id_token") as decode_token,
            mock.patch.object(xyn_api_module.requests, "post") as post_request,
        ):
            get_config.return_value = {"token_endpoint": "https://issuer.example.com/token"}
            resolve_secret.return_value = "secret"
            decode_token.return_value = {
                "sub": "sub-123",
                "email": "dev@xyence.io",
                "name": "Dev User",
            }
            post_request.side_effect = self._mock_token_post
            response = self.client.get("/auth/callback?code=abc&state=state-123")
        self.assertEqual(response.status_code, 302)
        session = self.client.session
        self.assertIn("user_identity_id", session)
        identity.refresh_from_db()
        self.assertEqual(identity.email, "dev@xyence.io")

    def test_me_endpoint_requires_auth(self):
        response = self.client.get("/xyn/api/me")
        self.assertEqual(response.status_code, 401)

    def test_role_required_denies_without_binding(self):
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="sub-123",
        )
        request = RequestFactory().get("/protected")
        middleware = SessionMiddleware(lambda req: None)
        middleware.process_request(request)
        request.session["user_identity_id"] = str(identity.id)
        request.session.save()

        @xyn_api_module.require_role("platform_admin")
        def _view(req):
            return JsonResponse({"ok": True})

        response = _view(request)
        self.assertEqual(response.status_code, 403)

    def test_first_admin_bootstrap_guarded(self):
        env = self._make_env()
        session = self.client.session
        session["oidc_state"] = "state-123"
        session["oidc_nonce"] = "nonce-123"
        session["environment_id"] = str(env.id)
        session.save()
        with (
            mock.patch.dict(os.environ, {"ALLOW_FIRST_ADMIN_BOOTSTRAP": "true"}),
            mock.patch.object(xyn_api_module, "_get_oidc_config") as get_config,
            mock.patch.object(xyn_api_module, "_resolve_secret_ref") as resolve_secret,
            mock.patch.object(xyn_api_module, "_decode_id_token") as decode_token,
            mock.patch.object(xyn_api_module.requests, "post") as post_request,
        ):
            get_config.return_value = {"token_endpoint": "https://issuer.example.com/token"}
            resolve_secret.return_value = "secret"
            decode_token.return_value = {
                "sub": "sub-abc",
                "email": "admin@xyence.io",
                "name": "Admin User",
            }
            post_request.side_effect = self._mock_token_post
            response = self.client.get("/auth/callback?code=abc&state=state-123")
        self.assertEqual(response.status_code, 302)
        identity = UserIdentity.objects.get(subject="sub-abc")
        self.assertTrue(RoleBinding.objects.filter(user_identity=identity, role="platform_admin").exists())

    def test_environment_resolution_prefers_host_mapping(self):
        env = self._make_env()
        env.metadata_json = {"oidc": env.metadata_json["oidc"], "hosts": ["auth.xyence.io"]}
        env.save(update_fields=["metadata_json", "updated_at"])
        request = RequestFactory().get("/auth/login", HTTP_X_FORWARDED_HOST="auth.xyence.io")
        resolved = xyn_api_module._resolve_environment(request)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.id, env.id)

    def test_environment_query_param_disabled_by_default(self):
        env = self._make_env()
        other = Environment.objects.create(name="Other", slug="other")
        request = RequestFactory().get(f"/auth/login?environment_id={other.id}")
        resolved = xyn_api_module._resolve_environment(request)
        self.assertIsNotNone(resolved)
        self.assertNotEqual(resolved.id, other.id)

    def test_environment_resolution_supports_wildcards(self):
        env = self._make_env()
        env.metadata_json = {"oidc": env.metadata_json["oidc"], "hosts": ["*.xyence.io"]}
        env.save(update_fields=["metadata_json", "updated_at"])
        request = RequestFactory().get("/auth/login", HTTP_X_FORWARDED_HOST="ems.xyence.io")
        resolved = xyn_api_module._resolve_environment(request)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.id, env.id)


class PlatformAdminTests(TestCase):
    def _set_admin_session(self):
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="sub-admin",
            email="admin@xyence.io",
        )
        RoleBinding.objects.create(user_identity=identity, scope_kind="platform", role="platform_admin")
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()
        return identity

    def test_tenants_crud_requires_platform_admin(self):
        response = self.client.get("/xyn/internal/tenants")
        self.assertEqual(response.status_code, 401)
        self._set_admin_session()
        response = self.client.post(
            "/xyn/internal/tenants",
            data=json.dumps({"name": "Acme", "slug": "acme"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        tenant_id = response.json().get("id")
        response = self.client.get("/xyn/internal/tenants")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(t["id"] == tenant_id for t in response.json().get("tenants", [])))

    def test_contacts_crud_requires_platform_admin(self):
        self._set_admin_session()
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        response = self.client.post(
            f"/xyn/internal/tenants/{tenant.id}/contacts",
            data=json.dumps({"name": "Pat", "email": "pat@acme.io"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        contact_id = response.json().get("id")
        response = self.client.get(f"/xyn/internal/contacts/{contact_id}")
        self.assertEqual(response.status_code, 200)

    def test_my_tenants_requires_auth(self):
        response = self.client.get("/xyn/api/tenants")
        self.assertEqual(response.status_code, 401)

    def test_non_platform_admin_cannot_access_other_tenants(self):
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="sub-user",
        )
        TenantMembership.objects.create(tenant=tenant, user_identity=identity, role="tenant_viewer")
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()
        other = Tenant.objects.create(name="Other", slug="other")
        response = self.client.get(f"/xyn/internal/tenants/{other.id}/contacts")
        self.assertEqual(response.status_code, 403)

    def test_tenant_admin_can_manage_contacts(self):
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="sub-user",
        )
        TenantMembership.objects.create(tenant=tenant, user_identity=identity, role="tenant_admin")
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()
        response = self.client.post(
            f"/xyn/internal/tenants/{tenant.id}/contacts",
            data=json.dumps({"name": "Pat", "email": "pat@acme.io"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)

    def test_tenant_viewer_cannot_modify_contacts(self):
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="sub-user",
        )
        TenantMembership.objects.create(tenant=tenant, user_identity=identity, role="tenant_viewer")
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()
        response = self.client.post(
            f"/xyn/internal/tenants/{tenant.id}/contacts",
            data=json.dumps({"name": "Pat", "email": "pat@acme.io"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)

    def test_platform_admin_bypasses_membership_checks(self):
        self._set_admin_session()
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        response = self.client.post(
            f"/xyn/internal/tenants/{tenant.id}/contacts",
            data=json.dumps({"name": "Admin", "email": "admin@acme.io"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)

    def test_branding_requires_membership(self):
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer.example.com", subject="sub-user")
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()
        response = self.client.get(f"/xyn/api/tenants/{tenant.id}/branding")
        self.assertEqual(response.status_code, 403)

    def test_tenant_admin_can_update_branding(self):
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer.example.com", subject="sub-user")
        TenantMembership.objects.create(tenant=tenant, user_identity=identity, role="tenant_admin")
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()
        response = self.client.patch(
            f"/xyn/internal/tenants/{tenant.id}/branding",
            data=json.dumps({"display_name": "Acme Corp", "logo_url": "https://example.com/logo.png"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        profile = BrandProfile.objects.get(tenant=tenant)
        self.assertEqual(profile.display_name, "Acme Corp")

    def test_default_branding_fallback(self):
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer.example.com", subject="sub-user")
        TenantMembership.objects.create(tenant=tenant, user_identity=identity, role="tenant_viewer")
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()
        response = self.client.get(f"/xyn/api/tenants/{tenant.id}/branding")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("display_name", body)
        self.assertIn("logo_url", body)

    def test_platform_admin_can_edit_any_branding(self):
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        self._set_admin_session()
        response = self.client.patch(
            f"/xyn/internal/tenants/{tenant.id}/branding",
            data=json.dumps({"display_name": "Platform Edit"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)

    def test_device_crud_requires_active_tenant(self):
        self._set_admin_session()
        response = self.client.get("/xyn/api/tenant/devices")
        self.assertEqual(response.status_code, 400)

    def test_viewer_cannot_modify_device(self):
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer.example.com", subject="sub-user")
        TenantMembership.objects.create(tenant=tenant, user_identity=identity, role="tenant_viewer")
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session["active_tenant_id"] = str(tenant.id)
        session.save()
        response = self.client.post(
            "/xyn/api/tenant/devices",
            data=json.dumps({"name": "dev1", "device_type": "router"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)

    def test_operator_can_modify_device(self):
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer.example.com", subject="sub-user")
        TenantMembership.objects.create(tenant=tenant, user_identity=identity, role="tenant_operator")
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session["active_tenant_id"] = str(tenant.id)
        session.save()
        response = self.client.post(
            "/xyn/api/tenant/devices",
            data=json.dumps({"name": "dev1", "device_type": "router"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)

    def test_platform_admin_can_access_any_device(self):
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        device = Device.objects.create(tenant=tenant, name="dev1", device_type="router")
        self._set_admin_session()
        response = self.client.get(f"/xyn/api/devices/{device.id}")
        self.assertEqual(response.status_code, 200)

    def test_device_unique_name_per_tenant(self):
        tenant = Tenant.objects.create(name="Acme", slug="acme")
        Device.objects.create(tenant=tenant, name="dev1", device_type="router")
        self._set_admin_session()
        session = self.client.session
        session["active_tenant_id"] = str(tenant.id)
        session.save()
        response = self.client.post(
            "/xyn/api/tenant/devices",
            data=json.dumps({"name": "dev1", "device_type": "router"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)


class AdminBridgeTests(TestCase):
    def _make_env(self):
        return Environment.objects.create(name="Dev", slug="dev")

    def _set_admin_session(self):
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="sub-admin",
            email="admin@xyence.io",
        )
        RoleBinding.objects.create(user_identity=identity, scope_kind="platform", role="platform_admin")
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()
        return identity

    def _seed_session(self, client, env):
        session = client.session
        session["oidc_state"] = "state-123"
        session["oidc_nonce"] = "nonce-123"
        session["environment_id"] = str(env.id)
        session.save()

    def _mock_oidc(self, claims, roles):
        identity, _ = UserIdentity.objects.get_or_create(
            issuer="https://accounts.google.com",
            subject=claims["sub"],
            defaults={"provider": "oidc", "email": claims.get("email")},
        )
        RoleBinding.objects.filter(user_identity=identity).delete()
        for role in roles:
            RoleBinding.objects.create(user_identity=identity, scope_kind="platform", role=role)

    def test_user_username_is_issuer_scoped_no_collision(self):
        env = self._make_env()
        self._seed_session(self.client, env)
        claims = {"sub": "sub-1", "email": "jrestivo@xyence.io", "name": "Josh"}
        with (
            mock.patch.object(xyn_api_module, "_get_oidc_config") as get_config,
            mock.patch.object(xyn_api_module, "_resolve_secret_ref") as resolve_secret,
            mock.patch.object(xyn_api_module, "_decode_id_token") as decode_token,
            mock.patch.object(xyn_api_module.requests, "post") as post_request,
        ):
            get_config.return_value = {"token_endpoint": "https://issuer.example.com/token"}
            resolve_secret.return_value = "secret"
            decode_token.return_value = claims
            post_request.return_value = type("Resp", (), {"status_code": 200, "json": lambda self: {"id_token": "tok"}})()
            self._mock_oidc(claims, ["platform_admin"])
            response = self.client.get("/auth/callback?code=abc&state=state-123")
        self.assertEqual(response.status_code, 302)
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.get(email="jrestivo@xyence.io")
        self.assertTrue(user.username.startswith("oidc:"))

    def test_staff_flag_revoked_when_platform_admin_removed(self):
        env = self._make_env()
        self._seed_session(self.client, env)
        claims = {"sub": "sub-2", "email": "user@xyence.io", "name": "User"}
        with (
            mock.patch.object(xyn_api_module, "_get_oidc_config") as get_config,
            mock.patch.object(xyn_api_module, "_resolve_secret_ref") as resolve_secret,
            mock.patch.object(xyn_api_module, "_decode_id_token") as decode_token,
            mock.patch.object(xyn_api_module.requests, "post") as post_request,
        ):
            get_config.return_value = {"token_endpoint": "https://issuer.example.com/token"}
            resolve_secret.return_value = "secret"
            decode_token.return_value = claims
            post_request.return_value = type("Resp", (), {"status_code": 200, "json": lambda self: {"id_token": "tok"}})()
            self._mock_oidc(claims, ["platform_admin"])
            self.client.get("/auth/callback?code=abc&state=state-123")
            self._mock_oidc(claims, [])
            self.client.get("/auth/callback?code=abc&state=state-123")
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.get(email="user@xyence.io")
        self.assertFalse(user.is_staff)

    def test_admin_denied_without_platform_admin_even_if_staff_true(self):
        from django.contrib.auth import get_user_model
        from django.contrib import admin as django_admin

        env = self._make_env()
        identity = UserIdentity.objects.create(
            issuer="https://accounts.google.com",
            subject="sub-3",
            provider="oidc",
            email="staff@xyence.io",
        )
        User = get_user_model()
        user = User.objects.create(username="staff@xyence.io", email="staff@xyence.io", is_staff=True, is_active=True)
        request = RequestFactory().get("/admin/")
        request.user = user
        middleware = SessionMiddleware(lambda req: None)
        middleware.process_request(request)
        request.session["user_identity_id"] = str(identity.id)
        request.session.save()
        self.assertFalse(django_admin.site.has_permission(request))

    def test_role_binding_create_delete_requires_platform_admin(self):
        self._set_admin_session()
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="sub-user",
        )
        response = self.client.post(
            "/xyn/internal/role_bindings",
            data=json.dumps({"user_identity_id": str(identity.id), "role": "platform_operator"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        binding_id = response.json().get("id")
        response = self.client.delete(f"/xyn/internal/role_bindings/{binding_id}")
        self.assertEqual(response.status_code, 200)

    def test_identities_list_requires_platform_admin(self):
        UserIdentity.objects.create(provider="oidc", issuer="https://issuer.example.com", subject="sub")
        response = self.client.get("/xyn/internal/identities")
        self.assertEqual(response.status_code, 401)
        self._set_admin_session()
        response = self.client.get("/xyn/internal/identities")
        self.assertEqual(response.status_code, 200)
        self.assertIn("identities", response.json())


class PipelineSchemaTests(TestCase):
    def _load_schema(self, name: str) -> dict:
        path = Path(__file__).resolve().parents[2] / "schemas" / name
        return json.loads(path.read_text(encoding="utf-8"))

    def test_implementation_plan_schema_for_ems(self):
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        plan = _generate_implementation_plan(blueprint)
        schema = self._load_schema("implementation_plan.v1.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(plan))
        self.assertEqual(errors, [], f"Schema errors: {errors}")
        self.assertGreaterEqual(len(plan.get("work_items", [])), 1)
        chassis = next((w for w in plan.get("work_items", []) if w.get("id") == "ems-stack-prod-web"), None)
        self.assertIsNotNone(chassis)
        verify_cmds = [entry.get("command", "") for entry in chassis.get("verify", [])]
        self.assertTrue(any("scripts/verify.sh" in cmd for cmd in verify_cmds))
        self.assertIn("plan_rationale", plan)
        self.assertIn("module_catalog.v1.json", chassis.get("inputs", {}).get("artifacts", []))
        self.assertIn("run_history_summary.v1.json", chassis.get("inputs", {}).get("artifacts", []))

    def test_codegen_result_schema(self):
        schema = self._load_schema("codegen_result.v1.schema.json")
        payload = {
            "schema_version": "codegen_result.v1",
            "task_id": "task-1",
            "work_item_id": "ems-api-scaffold",
            "blueprint_id": "bp-1",
            "summary": {
                "outcome": "succeeded",
                "changes": "1 repo updated",
                "risks": "scaffold only",
                "next_steps": "review",
            },
            "repo_results": [
                {
                    "repo": {
                        "name": "xyn-api",
                        "url": "https://github.com/Xyence/xyn-api",
                        "ref": "main",
                        "path_root": "apps/ems-api",
                    },
                    "files_changed": ["apps/ems-api/README.md"],
                    "patches": [{"path_hint": "apps/ems-api", "diff_unified": "diff --git"}],
                    "commands_executed": [
                        {"command": "test -f apps/ems-api/README.md", "cwd": ".", "exit_code": 0}
                    ],
                }
            ],
            "artifacts": [
                {"key": "codegen_patch_xyn-api.diff", "content_type": "text/x-diff", "description": "diff"}
            ],
            "success": True,
            "started_at": "2026-02-06T00:00:00Z",
            "finished_at": "2026-02-06T00:00:01Z",
            "errors": [],
        }
        errors = list(Draft202012Validator(schema).iter_errors(payload))
        self.assertEqual(errors, [], f"Schema errors: {errors}")

    def test_context_pack_selection_respects_purpose(self):
        ContextPack.objects.create(
            name="any-pack",
            purpose="any",
            scope="global",
            version="1",
            content_markdown="any",
            is_default=True,
        )
        ContextPack.objects.create(
            name="planner-pack",
            purpose="planner",
            scope="global",
            version="1",
            content_markdown="planner",
            is_default=True,
        )
        ContextPack.objects.create(
            name="coder-pack",
            purpose="coder",
            scope="global",
            version="1",
            content_markdown="coder",
            is_default=True,
        )
        ContextPack.objects.create(
            name="ems-pack",
            purpose="planner",
            scope="project",
            project_key="core.ems.platform",
            version="1",
            content_markdown="ems",
        )
        coder_packs = _select_context_packs_for_dev_task("coder", "core", "core.ems.platform", "codegen")
        coder_names = {p.name for p in coder_packs}
        self.assertIn("any-pack", coder_names)
        self.assertIn("coder-pack", coder_names)
        self.assertNotIn("planner-pack", coder_names)

        planner_packs = _select_context_packs_for_dev_task("planner", "core", "core.ems.platform", "release_plan_generate")
        planner_names = {p.name for p in planner_packs}
        self.assertIn("any-pack", planner_names)
        self.assertIn("planner-pack", planner_names)
        self.assertIn("ems-pack", planner_names)

    def test_module_catalog_schema(self):
        catalog = _build_module_catalog()
        schema = self._load_schema("module_catalog.v1.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(catalog))
        self.assertEqual(errors, [], f"Schema errors: {errors}")
        self.assertGreaterEqual(len(catalog.get("modules", [])), 1)

    def test_run_history_summary_schema(self):
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        summary = _build_run_history_summary(blueprint)
        schema = self._load_schema("run_history_summary.v1.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(summary))
        self.assertEqual(errors, [], f"Schema errors: {errors}")

    def test_deploy_result_schema(self):
        payload = {
            "schema_version": "deploy_result.v1",
            "target_instance": {"id": "inst-1", "name": "xyn-seed-dev-1"},
            "fqdn": "ems.xyence.io",
            "ssm_command_id": "cmd-123",
            "outcome": "noop",
            "changes": "No changes (already healthy)",
            "verification": [
                {"name": "public_health", "ok": True, "detail": "200"},
                {"name": "public_api_health", "ok": True, "detail": "200"},
                {"name": "dns_record", "ok": True, "detail": "match"},
                {"name": "ssm_preflight", "ok": True, "detail": "skipped"},
                {"name": "ssm_local_health", "ok": True, "detail": "skipped"},
            ],
            "started_at": "2024-01-01T00:00:00Z",
            "finished_at": "2024-01-01T00:00:10Z",
            "errors": [],
        }
        schema = self._load_schema("deploy_result.v1.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(payload))
        self.assertEqual(errors, [], f"Schema errors: {errors}")

    def test_acme_result_schema(self):
        payload = {
            "schema_version": "acme_result.v1",
            "fqdn": "ems.xyence.io",
            "email": "admin@xyence.io",
            "method": "http-01",
            "outcome": "succeeded",
            "issued_at": "2026-02-07T00:00:00Z",
            "expiry_not_after": "2026-05-01T00:00:00Z",
            "errors": [],
        }
        schema = self._load_schema("acme_result.v1.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(payload))
        self.assertEqual(errors, [], f"Schema errors: {errors}")

    def test_build_result_schema(self):
        payload = {
            "schema_version": "build_result.v1",
            "release_id": "rel-1",
            "images": [
                {
                    "name": "ems-api",
                    "repository": "xyn/ems-api",
                    "tag": "rel-1",
                    "image_uri": "123.dkr.ecr.us-west-2.amazonaws.com/xyn/ems-api:rel-1",
                    "digest": "sha256:abc",
                    "pushed": True,
                }
            ],
            "outcome": "succeeded",
            "started_at": "2026-02-07T00:00:00Z",
            "finished_at": "2026-02-07T00:00:10Z",
            "errors": [{"code": "none", "message": "ok"}],
        }
        schema = self._load_schema("build_result.v1.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(payload))
        self.assertEqual(errors, [], f"Schema errors: {errors}")

    def test_release_manifest_schema(self):
        payload = {
            "schema_version": "release_manifest.v1",
            "release_id": "rel-1",
            "blueprint_id": str(uuid.uuid4()),
            "release_target_id": str(uuid.uuid4()),
            "images": {"ems-api": {"image_uri": "repo:tag", "digest": "sha256:abc"}},
            "compose": {"file_path": "compose.release.yml", "content_hash": "abc"},
            "created_at": "2026-02-07T00:00:00Z",
        }
        schema = self._load_schema("release_manifest.v1.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(payload))
        self.assertEqual(errors, [], f"Schema errors: {errors}")

    def test_release_target_schema_validates(self):
        payload = {
            "schema_version": "release_target.v1",
            "id": str(uuid.uuid4()),
            "blueprint_id": str(uuid.uuid4()),
            "name": "manager-demo",
            "environment": "manager-demo",
            "target_instance_id": str(uuid.uuid4()),
            "fqdn": "ems.xyence.io",
            "dns": {"provider": "route53", "zone_name": "xyence.io", "record_type": "A", "ttl": 60},
            "runtime": {
                "type": "docker-compose",
                "transport": "ssm",
                "mode": "compose_build",
                "remote_root": "/opt/xyn/apps/ems",
            },
            "tls": {"mode": "nginx+acme", "acme_email": "admin@xyence.io", "redirect_http_to_https": True},
            "env": {"EMS_JWT_SECRET": "dev-secret"},
            "secret_refs": [],
            "created_at": "2026-02-07T00:00:00Z",
            "updated_at": "2026-02-07T00:00:00Z",
        }
        schema = self._load_schema("release_target.v1.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(payload))
        self.assertEqual(errors, [], f"Schema errors: {errors}")

    def test_release_target_schema_requires_mode_for_docker_compose(self):
        payload = {
            "schema_version": "release_target.v1",
            "id": str(uuid.uuid4()),
            "blueprint_id": str(uuid.uuid4()),
            "name": "manager-demo",
            "target_instance_id": str(uuid.uuid4()),
            "fqdn": "ems.xyence.io",
            "dns": {"provider": "route53"},
            "runtime": {"type": "docker-compose", "transport": "ssm"},
            "tls": {"mode": "none"},
            "created_at": "2026-02-07T00:00:00Z",
            "updated_at": "2026-02-07T00:00:00Z",
        }
        schema = self._load_schema("release_target.v1.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(payload))
        self.assertTrue(errors)

    def test_release_target_secret_ref_validation(self):
        payload = {
            "schema_version": "release_target.v1",
            "id": str(uuid.uuid4()),
            "blueprint_id": str(uuid.uuid4()),
            "name": "manager-demo",
            "target_instance_id": str(uuid.uuid4()),
            "fqdn": "ems.xyence.io",
            "dns": {"provider": "route53"},
            "runtime": {"type": "docker-compose", "transport": "ssm"},
            "tls": {"mode": "none"},
            "secret_refs": [
                {"name": "ems_jwt_secret", "ref": "ssm:/xyn/ems/jwt"},
                {"name": "EMS_JWT_SECRET", "ref": "vault:/bad"},
            ],
            "created_at": "2026-02-07T00:00:00Z",
            "updated_at": "2026-02-07T00:00:00Z",
        }
        errors = _validate_release_target_payload(payload)
        self.assertTrue(any("secret_refs[0].name" in err for err in errors))
        self.assertTrue(any("secret_refs[1].ref" in err for err in errors))

    @mock.patch("xyn_orchestrator.worker_tasks.boto3.client")
    def test_secret_resolution_merges_and_overrides_env(self, mock_client):
        ssm_mock = mock.Mock()
        ssm_mock.get_parameter.return_value = {"Parameter": {"Value": "good-secret"}}
        mock_client.return_value = ssm_mock
        env = {"EMS_JWT_SECRET": "bad-secret", "EMS_JWT_ISSUER": "xyn-ems"}
        secret_refs = [{"name": "EMS_JWT_SECRET", "ref": "ssm:/xyn/ems/jwt"}]
        merged, secret_values, secret_keys = _merge_release_env(env, secret_refs, "us-west-2")
        self.assertEqual(merged["EMS_JWT_SECRET"], "good-secret")
        self.assertEqual(secret_values["EMS_JWT_SECRET"], "good-secret")
        self.assertIn("EMS_JWT_SECRET", secret_keys)

    def test_redaction_removes_secret_from_logs(self):
        text = "token=supersecret and again supersecret"
        redacted = _redact_secrets(text, {"EMS_JWT_SECRET": "supersecret"})
        self.assertNotIn("supersecret", redacted)
        self.assertIn("***REDACTED***", redacted)

    def test_manifest_does_not_include_secret_values(self):
        manifest = _build_deploy_manifest(
            "ems.xyence.io",
            {"id": "inst-1"},
            "/opt/xyn/apps/ems",
            "apps/ems-stack/docker-compose.yml",
            {"EMS_JWT_ISSUER": "xyn-ems"},
            ["EMS_JWT_SECRET"],
        )
        payload = json.dumps(manifest)
        self.assertIn("EMS_JWT_SECRET", payload)
        self.assertNotIn("supersecret", payload)

    def test_planner_selects_persistence_slice(self):
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        for work_item_id in [
            "ems-stack-prod-web",
            "ems-api-jwt-protect-me",
            "ems-stack-pass-jwt-secret-and-verify-me",
            "ems-api-devices-rbac",
            "ems-stack-verify-rbac",
        ]:
            run = Run.objects.create(
                entity_type="dev_task",
                entity_id=uuid.uuid4(),
                status="succeeded",
            )
            _write_run_artifact(
                run,
                "codegen_result.json",
                {"success": True, "repo_results": []},
                "codegen_result",
            )
            DevTask.objects.create(
                title=work_item_id,
                task_type="codegen",
                status="succeeded",
                source_entity_type="blueprint",
                source_entity_id=blueprint.id,
                work_item_id=work_item_id,
                result_run=run,
            )
        module_catalog = _build_module_catalog()
        run_history = _build_run_history_summary(blueprint)
        plan = _generate_implementation_plan(
            blueprint,
            module_catalog=module_catalog,
            run_history_summary=run_history,
        )
        ids = {item.get("id") for item in plan.get("work_items", [])}
        self.assertIn("ems-api-devices-postgres", ids)
        self.assertIn("ems-stack-verify-persistence", ids)
        self.assertNotIn("ems-api-jwt-protect-me", ids)
        self.assertNotIn("ems-api-devices-rbac", ids)
        rationale = plan.get("plan_rationale", {})
        self.assertIn("persistence_devices", rationale.get("gaps_detected", []))
        sample = next(iter(plan.get("work_items", [])))
        self.assertIn("capabilities_required", sample)
        self.assertIn("module_refs", sample)

    def test_planner_selects_route53_module_scaffold(self):
        blueprint = Blueprint.objects.create(
            name="ems.platform",
            namespace="core",
            metadata_json={"dns_provider": "route53"},
        )
        module_catalog = _build_module_catalog()
        module_catalog["modules"] = [m for m in module_catalog.get("modules", []) if m.get("id") != "dns-route53"]
        run_history = _build_run_history_summary(blueprint)
        plan = _generate_implementation_plan(
            blueprint,
            module_catalog=module_catalog,
            run_history_summary=run_history,
        )
        ids = {item.get("id") for item in plan.get("work_items", [])}
        self.assertIn("dns-route53-module", ids)

    def test_planner_selects_image_deploy_when_enabled(self):
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        release_target = {
            "schema_version": "release_target.v1",
            "id": str(uuid.uuid4()),
            "blueprint_id": str(blueprint.id),
            "name": "manager-demo",
            "target_instance_id": str(uuid.uuid4()),
            "fqdn": "ems.xyence.io",
            "dns": {"provider": "route53"},
            "runtime": {"type": "docker-compose", "transport": "ssm", "mode": "compose_images"},
            "tls": {"mode": "none"},
            "created_at": "2026-02-07T00:00:00Z",
            "updated_at": "2026-02-07T00:00:00Z",
        }
        plan = _generate_implementation_plan(blueprint, release_target=release_target)
        ids = {item.get("id") for item in plan.get("work_items", [])}
        self.assertIn("build.publish_images.container", ids)
        self.assertIn("deploy.apply_remote_compose.pull", ids)
        self.assertIn("release.validate_manifest.pinned", ids)

    def test_select_next_slice_includes_manifest_validation_when_image_deploy_present(self):
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        release_target = {
            "schema_version": "release_target.v1",
            "id": str(uuid.uuid4()),
            "blueprint_id": str(blueprint.id),
            "name": "manager-demo",
            "target_instance_id": str(uuid.uuid4()),
            "fqdn": "ems.xyence.io",
            "dns": {"provider": "route53"},
            "runtime": {"type": "docker-compose", "transport": "ssm", "mode": "compose_images"},
            "tls": {"mode": "none"},
            "created_at": "2026-02-07T00:00:00Z",
            "updated_at": "2026-02-07T00:00:00Z",
        }
        plan = _generate_implementation_plan(blueprint, release_target=release_target)
        run_history = {
            "acceptance_checks_status": [{"id": "remote_http_health", "status": "fail"}],
            "completed_work_items": [],
        }
        selected, _ = _select_next_slice(blueprint, plan.get("work_items", []), run_history)
        selected_ids = {item.get("id") for item in selected}
        self.assertIn("release.validate_manifest.pinned", selected_ids)

    def test_manifest_validation_fails_when_digest_missing(self):
        manifest = {"images": {"ems-api": {"image_uri": "repo:tag"}}}
        ok, errors = _validate_release_manifest_pinned(manifest)
        self.assertFalse(ok)
        self.assertTrue(errors)

    def test_manifest_validation_requires_compose_hash(self):
        manifest = {
            "images": {"ems-api": {"image_uri": "repo:tag", "digest": "sha256:" + "a" * 64}},
            "compose": {"content": "image@sha256:" + "a" * 64},
        }
        ok, errors = _validate_release_manifest_pinned(manifest)
        self.assertFalse(ok)
        self.assertTrue(any(err.get("code") == "compose_hash_missing" for err in errors))

    def test_noop_digest_normalization(self):
        digest = "SHA256:" + "A" * 64
        self.assertEqual(_normalize_sha256(digest), "a" * 64)

    def test_normalize_digest_preserves_prefix(self):
        digest = "SHA256:" + "A" * 64
        self.assertEqual(_normalize_digest(digest), "sha256:" + "a" * 64)

    def test_manifest_override_excludes_build_step(self):
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        release_target = {
            "schema_version": "release_target.v1",
            "id": str(uuid.uuid4()),
            "blueprint_id": str(blueprint.id),
            "name": "manager-demo",
            "target_instance_id": str(uuid.uuid4()),
            "fqdn": "ems.xyence.io",
            "dns": {"provider": "route53"},
            "runtime": {"type": "docker-compose", "transport": "ssm", "mode": "compose_images"},
            "tls": {"mode": "none"},
            "created_at": "2026-02-07T00:00:00Z",
            "updated_at": "2026-02-07T00:00:00Z",
        }
        plan = _generate_implementation_plan(blueprint, release_target=release_target, manifest_override=True)
        ids = {item.get("id") for item in plan.get("work_items", [])}
        self.assertNotIn("build.publish_images.container", ids)
        self.assertIn("release.validate_manifest.pinned", ids)
        self.assertIn("deploy.apply_remote_compose.pull", ids)

    def test_deploy_state_metadata_payload(self):
        payload = _build_deploy_state_metadata(
            release_target_id=str(uuid.uuid4()),
            release_id="rel-1",
            release_uuid=str(uuid.uuid4()),
            release_version="v1",
            manifest_run_id=str(uuid.uuid4()),
            manifest_hash="abc",
            compose_hash="def",
            outcome="succeeded",
        )
        self.assertEqual(payload.get("deploy_outcome"), "succeeded")
        self.assertEqual(payload.get("manifest", {}).get("content_hash"), "abc")
        self.assertEqual(payload.get("compose", {}).get("content_hash"), "def")

    def test_runtime_marker_commands_include_manifest_files(self):
        commands = _build_remote_pull_apply_commands(
            "/opt/xyn/apps/ems",
            "services:\n  ems-api:\n    image: test\n",
            "deadbeef",
            "{\"schema_version\":\"release_manifest.v1\"}",
            "bead",
            "rel-1",
            "rel-uuid-1",
            "us-west-2",
            "123456789012.dkr.ecr.us-west-2.amazonaws.com",
            {},
        )
        joined = "\n".join(commands)
        self.assertIn("release_manifest.json", joined)
        self.assertIn("release_manifest.sha256", joined)
        self.assertIn("release_id", joined)

    def test_ssm_service_digest_commands_include_label_filter(self):
        commands = _build_ssm_service_digest_commands(["api", "web"])
        joined = "\n".join(commands)
        self.assertIn("label=com.docker.compose.service=api", joined)
        self.assertIn("label=com.docker.compose.service=web", joined)

    def test_parse_service_digest_lines(self):
        lines = ["api=sha256:" + "a" * 64, "web=SHA256:" + "B" * 64]
        parsed = _parse_service_digest_lines(lines)
        self.assertEqual(parsed["api"], "sha256:" + "a" * 64)
        self.assertEqual(parsed["web"], "sha256:" + "b" * 64)

    def test_release_upsert_and_resolve(self):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        factory = RequestFactory()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        payload = {
            "blueprint_id": str(blueprint.id),
            "version": "rel-1",
            "status": "published",
            "artifacts_json": {"release_manifest": {"url": "http://example/manifest.json"}},
        }
        request = factory.post(
            "/xyn/internal/releases/upsert",
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        response = internal_release_upsert(request)
        self.assertEqual(response.status_code, 200)
        release = Release.objects.get(blueprint_id=blueprint.id, version="rel-1")
        resolve_request = factory.post(
            "/xyn/internal/releases/resolve",
            data=json.dumps({"release_version": "rel-1", "blueprint_id": str(blueprint.id)}),
            content_type="application/json",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        resolve_response = internal_release_resolve(resolve_request)
        self.assertEqual(resolve_response.status_code, 200)

    def test_release_upsert_rejects_published_overwrite(self):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        factory = RequestFactory()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        Release.objects.create(
            blueprint_id=blueprint.id,
            version="rel-2",
            status="published",
            artifacts_json={
                "release_manifest": {"sha256": "aaa"},
                "compose_file": {"sha256": "bbb"},
            },
        )
        payload = {
            "blueprint_id": str(blueprint.id),
            "version": "rel-2",
            "status": "published",
            "artifacts_json": {
                "release_manifest": {"sha256": "ccc"},
                "compose_file": {"sha256": "ddd"},
            },
        }
        request = factory.post(
            "/xyn/internal/releases/upsert",
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        response = internal_release_upsert(request)
        self.assertEqual(response.status_code, 409)

    @mock.patch("xyn_orchestrator.blueprints._ssm_fetch_runtime_marker")
    def test_current_release_and_drift(self, mock_marker):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        factory = RequestFactory()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        instance = ProvisionedInstance.objects.create(
            name="seed-1",
            status="running",
            instance_id="i-123",
            aws_region="us-west-2",
        )
        target = ReleaseTarget.objects.create(
            blueprint=blueprint,
            name="demo",
            target_instance=instance,
            fqdn="ems.xyence.io",
            config_json={},
        )
        Run.objects.create(
            entity_type="blueprint",
            entity_id=blueprint.id,
            status="succeeded",
            metadata_json={
                "release_target_id": str(target.id),
                "release_uuid": "rel-uuid",
                "release_version": "rel-1",
                "deploy_outcome": "succeeded",
                "manifest": {"content_hash": "aaa"},
                "compose": {"content_hash": "bbb"},
                "deployed_at": "2026-02-07T00:00:00Z",
            },
        )
        request = factory.get(
            f"/xyn/internal/release-targets/{target.id}/current_release",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        response = internal_release_target_current_release(request, str(target.id))
        self.assertEqual(response.status_code, 200)
        mock_marker.return_value = {"release_uuid": "rel-uuid", "manifest_sha256": "aaa", "compose_sha256": "bbb"}
        drift_request = factory.get(
            f"/xyn/internal/release-targets/{target.id}/check_drift",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        drift_response = internal_release_target_check_drift(drift_request, str(target.id))
        self.assertEqual(drift_response.status_code, 200)

    def test_deploy_lock_blocks_concurrent_runs(self):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        factory = RequestFactory()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        target = ReleaseTarget.objects.create(
            blueprint=blueprint,
            name="demo",
            fqdn="ems.xyence.io",
            config_json={},
        )
        active = Run.objects.create(
            entity_type="blueprint",
            entity_id=blueprint.id,
            status="running",
            metadata_json={"release_target_id": str(target.id)},
        )
        request = factory.post(
            f"/xyn/internal/release-targets/{target.id}/deploy_manifest",
            data=json.dumps({"manifest_run_id": str(uuid.uuid4())}),
            content_type="application/json",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        response = internal_release_target_deploy_manifest(request, str(target.id))
        self.assertEqual(response.status_code, 409)

    def test_deploy_latest_selects_newest_published_release(self):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        factory = RequestFactory()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        target = ReleaseTarget.objects.create(
            blueprint=blueprint,
            name="demo",
            fqdn="ems.xyence.io",
            config_json={},
        )
        Release.objects.create(blueprint_id=blueprint.id, version="v1", status="published")
        latest = Release.objects.create(blueprint_id=blueprint.id, version="v2", status="published")
        request = factory.get(
            f"/xyn/internal/releases/latest?blueprint_id={blueprint.id}",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        response = internal_releases_latest(request)
        self.assertEqual(response.status_code, 200)
        deploy_request = factory.post(
            f"/xyn/internal/release-targets/{target.id}/deploy_latest",
            data=json.dumps({}),
            content_type="application/json",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        with mock.patch("xyn_orchestrator.blueprints.internal_release_target_deploy_release") as deploy_release:
            deploy_release.return_value = JsonResponse({"run_id": "x"}, status=200)
            internal_release_target_deploy_latest(deploy_request, str(target.id))
            deploy_release.assert_called()

    def test_rollback_last_success_selects_prior_release(self):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        factory = RequestFactory()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        target = ReleaseTarget.objects.create(
            blueprint=blueprint,
            name="demo",
            fqdn="ems.xyence.io",
            config_json={},
        )
        Run.objects.create(
            entity_type="blueprint",
            entity_id=blueprint.id,
            status="succeeded",
            metadata_json={
                "release_target_id": str(target.id),
                "release_uuid": "rel-new",
                "release_version": "v2",
                "deploy_outcome": "succeeded",
            },
        )
        Run.objects.create(
            entity_type="blueprint",
            entity_id=blueprint.id,
            status="succeeded",
            metadata_json={
                "release_target_id": str(target.id),
                "release_uuid": "rel-old",
                "release_version": "v1",
                "deploy_outcome": "succeeded",
            },
        )
        rollback_request = factory.post(
            f"/xyn/internal/release-targets/{target.id}/rollback_last_success",
            data=json.dumps({}),
            content_type="application/json",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        with mock.patch("xyn_orchestrator.blueprints.internal_release_target_deploy_release") as deploy_release:
            deploy_release.return_value = JsonResponse({"run_id": "x"}, status=200)
            internal_release_target_rollback_last_success(rollback_request, str(target.id))
            deploy_release.assert_called()

    def test_releases_retention_report(self):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        factory = RequestFactory()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        r1 = Release.objects.create(blueprint_id=blueprint.id, version="v1", status="published")
        r2 = Release.objects.create(blueprint_id=blueprint.id, version="v2", status="published")
        request = factory.get(
            f"/xyn/internal/releases/retention_report?blueprint_id={blueprint.id}&keep=1",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        response = internal_releases_retention_report(request)
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content.decode("utf-8"))
        self.assertEqual(payload["totals"]["retained"], 1)

    def test_gc_requires_confirm(self):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        factory = RequestFactory()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        Release.objects.create(blueprint_id=blueprint.id, version="v1", status="published")
        request = factory.post(
            "/xyn/internal/releases/gc",
            data=json.dumps({"blueprint_id": str(blueprint.id), "keep": 0, "dry_run": False}),
            content_type="application/json",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        response = internal_releases_gc(request)
        self.assertEqual(response.status_code, 400)

    def test_gc_dry_run_does_not_modify_releases(self):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        factory = RequestFactory()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        rel = Release.objects.create(blueprint_id=blueprint.id, version="v1", status="published")
        request = factory.post(
            "/xyn/internal/releases/gc",
            data=json.dumps({"blueprint_id": str(blueprint.id), "keep": 0, "dry_run": True}),
            content_type="application/json",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        response = internal_releases_gc(request)
        self.assertEqual(response.status_code, 200)
        rel.refresh_from_db()
        self.assertEqual(rel.status, "published")

    def test_gc_marks_deprecated(self):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        factory = RequestFactory()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        rel = Release.objects.create(blueprint_id=blueprint.id, version="v1", status="published")
        request = factory.post(
            "/xyn/internal/releases/gc",
            data=json.dumps({"blueprint_id": str(blueprint.id), "keep": 0, "dry_run": False, "confirm": True}),
            content_type="application/json",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        response = internal_releases_gc(request)
        self.assertEqual(response.status_code, 200)
        rel.refresh_from_db()
        self.assertEqual(rel.status, "deprecated")

    def test_release_promote_returns_existing_release(self):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        factory = RequestFactory()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        source = Release.objects.create(
            blueprint_id=blueprint.id,
            version="v1",
            status="published",
            artifacts_json={"release_manifest": {"sha256": "aaa"}},
        )
        request = factory.post(
            "/xyn/internal/releases/promote",
            data=json.dumps({"release_uuid": str(source.id)}),
            content_type="application/json",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        response = internal_release_promote(request)
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content.decode("utf-8"))
        self.assertEqual(payload.get("id"), str(source.id))

    def test_release_promote_conflict(self):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        factory = RequestFactory()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        source = Release.objects.create(
            blueprint_id=blueprint.id,
            version="v1",
            status="published",
            artifacts_json={"release_manifest": {"sha256": "aaa"}},
        )
        Release.objects.create(
            blueprint_id=blueprint.id,
            version="v1",
            status="published",
            artifacts_json={"release_manifest": {"sha256": "aaa"}},
        )
        request = factory.post(
            "/xyn/internal/releases/promote",
            data=json.dumps({"release_uuid": str(source.id)}),
            content_type="application/json",
            HTTP_X_INTERNAL_TOKEN="test-token",
        )
        response = internal_release_promote(request)
        self.assertEqual(response.status_code, 409)

    def test_planner_selects_remote_deploy_slice(self):
        blueprint = Blueprint.objects.create(
            name="ems.platform",
            namespace="core",
            metadata_json={
                "dns_provider": "route53",
                "deploy": {"target_instance_id": str(uuid.uuid4()), "primary_fqdn": "ems.xyence.io"},
            },
        )
        module_catalog = _build_module_catalog()
        run_history = _build_run_history_summary(blueprint)
        plan = _generate_implementation_plan(
            blueprint,
            module_catalog=module_catalog,
            run_history_summary=run_history,
        )
        ids = {item.get("id") for item in plan.get("work_items", [])}
        self.assertIn("dns.ensure_record.route53", ids)
        self.assertIn("deploy.apply_remote_compose.ssm", ids)
        self.assertIn("verify.public_http", ids)
        module_ids = {
            ref.get("id")
            for item in plan.get("work_items", [])
            for ref in item.get("module_refs", [])
            if isinstance(ref, dict)
        }
        self.assertIn("dns-route53", module_ids)
        self.assertIn("deploy-ssm-compose", module_ids)

    def test_planner_selects_tls_slice_when_tls_enabled(self):
        blueprint = Blueprint.objects.create(
            name="ems.platform",
            namespace="core",
            metadata_json={
                "dns_provider": "route53",
                "deploy": {"target_instance_id": str(uuid.uuid4()), "primary_fqdn": "ems.xyence.io"},
                "tls": {"mode": "nginx+acme", "acme_email": "admin@xyence.io"},
            },
        )
        module_catalog = _build_module_catalog()
        run_history = _build_run_history_summary(blueprint)
        plan = _generate_implementation_plan(
            blueprint,
            module_catalog=module_catalog,
            run_history_summary=run_history,
        )
        ids = {item.get("id") for item in plan.get("work_items", [])}
        self.assertIn("tls.acme_http01", ids)
        self.assertIn("ingress.nginx_tls_configure", ids)
        self.assertIn("verify.public_https", ids)
        module_ids = {
            ref.get("id")
            for item in plan.get("work_items", [])
            for ref in item.get("module_refs", [])
            if isinstance(ref, dict)
        }
        self.assertIn("ingress-nginx-acme", module_ids)

    def test_planner_uses_release_target_for_remote_slices(self):
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core", metadata_json={})
        target = ReleaseTarget.objects.create(
            blueprint=blueprint,
            name="manager-demo",
            environment="manager-demo",
            target_instance_ref=str(uuid.uuid4()),
            fqdn="ems.xyence.io",
            dns_json={"provider": "route53", "zone_name": "xyence.io"},
            runtime_json={"type": "docker-compose", "transport": "ssm"},
            tls_json={"mode": "nginx+acme", "acme_email": "admin@xyence.io"},
            env_json={},
            secret_refs_json=[],
        )
        release_payload = _release_target_payload(target)
        module_catalog = _build_module_catalog()
        run_history = _build_run_history_summary(blueprint, release_payload)
        plan = _generate_implementation_plan(
            blueprint,
            module_catalog=module_catalog,
            run_history_summary=run_history,
            release_target=release_payload,
        )
        ids = {item.get("id") for item in plan.get("work_items", [])}
        self.assertIn("dns.ensure_record.route53", ids)
        self.assertIn("deploy.apply_remote_compose.ssm", ids)
        self.assertIn("tls.acme_http01", ids)
        self.assertIn("ingress.nginx_tls_configure", ids)
        self.assertIn("verify.public_https", ids)
        self.assertEqual(plan.get("release_target_id"), str(target.id))
        self.assertEqual(plan.get("release_target_name"), target.name)
        build_publish = next((item for item in plan.get("work_items", []) if item.get("id") == "build.publish_images.container"), None)
        self.assertIsNotNone(build_publish)
        self.assertIn("config", build_publish)
        schema = self._load_schema("implementation_plan.v1.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(plan))
        self.assertEqual(errors, [], f"Schema errors: {errors}")

    def test_planner_does_not_require_blueprint_metadata_deploy(self):
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core", metadata_json={})
        target = ReleaseTarget.objects.create(
            blueprint=blueprint,
            name="manager-demo",
            target_instance_ref=str(uuid.uuid4()),
            fqdn="ems.xyence.io",
            dns_json={"provider": "route53", "zone_name": "xyence.io"},
            runtime_json={"type": "docker-compose", "transport": "ssm"},
            tls_json={"mode": "none"},
        )
        release_payload = _release_target_payload(target)
        plan = _generate_implementation_plan(
            blueprint,
            module_catalog=_build_module_catalog(),
            run_history_summary=_build_run_history_summary(blueprint, release_payload),
            release_target=release_payload,
        )
        ids = {item.get("id") for item in plan.get("work_items", [])}
        self.assertIn("dns.ensure_record.route53", ids)
        self.assertIn("deploy.apply_remote_compose.ssm", ids)
        self.assertIn("verify.public_http", ids)

    def test_dns_noop_when_record_matches(self):
        with mock.patch("xyn_orchestrator.worker_tasks._ensure_route53_record") as ensure_record:
            with mock.patch("xyn_orchestrator.worker_tasks._verify_route53_record", return_value=True):
                result = _route53_ensure_with_noop("ems.xyence.io", "Z123", "1.2.3.4")
        self.assertEqual(result.get("outcome"), "noop")
        ensure_record.assert_not_called()

    def test_remote_deploy_noop_when_public_verify_passes(self):
        target_instance = {"id": "inst-1", "name": "xyn-seed-dev-1", "instance_id": "i-123", "aws_region": "us-west-2"}
        with mock.patch("xyn_orchestrator.worker_tasks._public_verify", return_value=(True, [])):
            with mock.patch("xyn_orchestrator.worker_tasks._run_ssm_commands") as run_ssm:
                payload = _run_remote_deploy("run-1", "ems.xyence.io", target_instance, "secret", None)
        self.assertEqual(payload.get("deploy_result", {}).get("outcome"), "noop")
        self.assertFalse(payload.get("ssm_invoked"))
        run_ssm.assert_not_called()

    def test_dns_route53_module_spec_fields(self):
        spec_path = Path(__file__).resolve().parents[2] / "registry" / "modules" / "dns-route53.json"
        data = json.loads(spec_path.read_text(encoding="utf-8"))
        self.assertEqual(data.get("kind"), "Module")
        metadata = data.get("metadata", {})
        self.assertEqual(metadata.get("name"), "dns-route53")
        self.assertEqual(metadata.get("namespace"), "core")
        module_spec = data.get("module", {})
        self.assertIn("dns.route53.records", module_spec.get("capabilitiesProvided", []))

    def test_runtime_web_static_module_spec_fields(self):
        spec_path = (
            Path(__file__).resolve().parents[2] / "registry" / "modules" / "runtime-web-static-nginx.json"
        )
        data = json.loads(spec_path.read_text(encoding="utf-8"))
        self.assertEqual(data.get("kind"), "Module")
        metadata = data.get("metadata", {})
        self.assertEqual(metadata.get("name"), "runtime-web-static-nginx")
        self.assertEqual(metadata.get("namespace"), "core")
        module_spec = data.get("module", {})
        self.assertIn("runtime.web.static", module_spec.get("capabilitiesProvided", []))
        self.assertIn("runtime.reverse_proxy.http", module_spec.get("capabilitiesProvided", []))

    def test_deploy_ssm_compose_module_spec_fields(self):
        spec_path = (
            Path(__file__).resolve().parents[2] / "registry" / "modules" / "deploy-ssm-compose.json"
        )
        data = json.loads(spec_path.read_text(encoding="utf-8"))
        self.assertEqual(data.get("kind"), "Module")
        metadata = data.get("metadata", {})
        self.assertEqual(metadata.get("name"), "deploy-ssm-compose")
        self.assertEqual(metadata.get("namespace"), "core")
        module_spec = data.get("module", {})
        self.assertIn("runtime.compose.apply_remote", module_spec.get("capabilitiesProvided", []))

    def test_ingress_nginx_acme_module_spec_fields(self):
        spec_path = (
            Path(__file__).resolve().parents[2] / "registry" / "modules" / "ingress-nginx-acme.json"
        )
        data = json.loads(spec_path.read_text(encoding="utf-8"))
        self.assertEqual(data.get("kind"), "Module")
        metadata = data.get("metadata", {})
        self.assertEqual(metadata.get("name"), "ingress-nginx-acme")
        self.assertEqual(metadata.get("namespace"), "core")
        module_spec = data.get("module", {})
        self.assertIn("ingress.tls.acme_http01", module_spec.get("capabilitiesProvided", []))
        self.assertIn("ingress.nginx.reverse_proxy", module_spec.get("capabilitiesProvided", []))

    def test_prod_web_scaffold_outputs(self):
        work_item = {
            "id": "ems-stack-prod-web",
            "repo_targets": [
                {
                    "name": "xyn-api",
                    "url": "https://example.com/xyn-api",
                    "ref": "main",
                    "path_root": "apps/ems-stack",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            _apply_scaffold_for_work_item(work_item, repo_dir)
            compose = Path(repo_dir, "apps/ems-stack/docker-compose.yml").read_text(encoding="utf-8")
            self.assertIn("ems-web", compose)
            self.assertNotIn("5173", compose)
            self.assertNotIn("npm run dev", compose)
            self.assertIn("EMS_PUBLIC_TLS_PORT", compose)
            self.assertIn("acme-webroot", compose)

    def test_ui_dockerfile_builds_static_assets(self):
        work_item = {
            "id": "ems-ui-scaffold",
            "repo_targets": [
                {
                    "name": "xyn-ui",
                    "url": "https://example.com/xyn-ui",
                    "ref": "main",
                    "path_root": "apps/ems-ui",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            _apply_scaffold_for_work_item(work_item, repo_dir)
            dockerfile = Path(repo_dir, "apps/ems-ui/Dockerfile").read_text(encoding="utf-8")
            self.assertIn("npm ci", dockerfile)
            self.assertIn("npm run build", dockerfile)
            nginx_conf = Path(repo_dir, "apps/ems-ui/nginx.conf").read_text(encoding="utf-8")
            self.assertIn("listen 8443 ssl", nginx_conf)
            self.assertIn(".well-known/acme-challenge", nginx_conf)

    def test_codegen_patch_can_apply_to_clean_repo(self):
        if shutil.which("git") is None:
            self.skipTest("git not available")
        work_item = {
            "id": "ems-api-scaffold",
            "repo_targets": [
                {
                    "name": "xyn-api",
                    "url": "https://example.com/xyn-api",
                    "ref": "main",
                    "path_root": "apps/ems-api",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            subprocess.run(["git", "init"], cwd=repo_dir, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)
            Path(repo_dir, ".gitignore").write_text("# test\n", encoding="utf-8")
            subprocess.run(["git", "add", ".gitignore"], cwd=repo_dir, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=repo_dir, check=True)

            _apply_scaffold_for_work_item(work_item, repo_dir)
            diff = _collect_git_diff(repo_dir)
            self.assertIn("apps/ems-api/ems_api/main.py", diff)

            subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=repo_dir, check=True)
            subprocess.run(["git", "apply", "-"], input=diff, text=True, cwd=repo_dir, check=True)
            self.assertTrue(Path(repo_dir, "apps/ems-api/ems_api/main.py").exists())

    def test_scaffold_verify_commands(self):
        scaffold = {
            "id": "ems-api-scaffold",
            "repo_targets": [
                {
                    "name": "xyn-api",
                    "url": "https://example.com/xyn-api",
                    "ref": "main",
                    "path_root": "apps/ems-api",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        devices_rbac = {
            "id": "ems-api-devices-rbac",
            "repo_targets": [
                {
                    "name": "xyn-api",
                    "url": "https://example.com/xyn-api",
                    "ref": "main",
                    "path_root": "apps/ems-api",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            _apply_scaffold_for_work_item(scaffold, repo_dir)
            _apply_scaffold_for_work_item(devices_rbac, repo_dir)
            app_root = Path(repo_dir, "apps/ems-api")
            env = os.environ.copy()
            compile_result = subprocess.run(
                ["python", "-m", "compileall", "ems_api"],
                cwd=app_root,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            import_result = subprocess.run(
                ["python", "-c", "import ems_api.main"],
                cwd=app_root,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(import_result.returncode, 0, import_result.stderr)

    def test_codegen_no_changes_marks_failure(self):
        errors = []
        success, noop = _mark_noop_codegen(False, "noop-item", errors, verify_ok=False)
        self.assertFalse(success)
        self.assertFalse(noop)
        self.assertEqual(errors[0]["code"], "no_changes")

    def test_ui_scaffold_writes_imports(self):
        work_item = {
            "id": "ems-ui-scaffold",
            "repo_targets": [
                {
                    "name": "xyn-ui",
                    "url": "https://example.com/xyn-ui",
                    "ref": "main",
                    "path_root": "apps/ems-ui",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            _apply_scaffold_for_work_item(work_item, repo_dir)
            app_root = Path(repo_dir, "apps/ems-ui/src")
            expected = [
                "App.tsx",
                "main.tsx",
                "routes.tsx",
                "auth/Login.tsx",
                "devices/DeviceList.tsx",
                "reports/Reports.tsx",
            ]
            for rel in expected:
                self.assertTrue((app_root / rel).exists(), rel)

    def test_compose_chassis_outputs(self):
        work_item = {
            "id": "ems-stack-prod-web",
            "repo_targets": [
                {
                    "name": "xyn-api",
                    "url": "https://example.com/xyn-api",
                    "ref": "main",
                    "path_root": "apps/ems-stack",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            _apply_scaffold_for_work_item(work_item, repo_dir)
            root = Path(repo_dir, "apps/ems-stack")
            compose_path = root / "docker-compose.yml"
            nginx_path = root / "nginx/nginx.conf"
            verify_path = root / "scripts/verify.sh"
            self.assertTrue(compose_path.exists())
            self.assertTrue(nginx_path.exists())
            self.assertTrue(verify_path.exists())
            data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
            self.assertIn("services", data)
            for service in ["ems-api", "ems-web", "postgres"]:
                self.assertIn(service, data["services"])
            self.assertIn("XYN_UI_PATH", compose_path.read_text(encoding="utf-8"))
            verify_contents = verify_path.read_text(encoding="utf-8")
            self.assertIn("/health", verify_contents)
            self.assertIn("/api/health", verify_contents)
            self.assertIn("/api/me", verify_contents)
            self.assertIn("Expected /api/me", verify_contents)
            self.assertIn("Health check failed", verify_contents)

    def test_ui_login_uses_api_health(self):
        work_item = {
            "id": "ems-ui-scaffold",
            "repo_targets": [
                {
                    "name": "xyn-ui",
                    "url": "https://example.com/xyn-ui",
                    "ref": "main",
                    "path_root": "apps/ems-ui",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            _apply_scaffold_for_work_item(work_item, repo_dir)
            login_path = Path(repo_dir, "apps/ems-ui/src/auth/Login.tsx")
            self.assertTrue(login_path.exists())
            self.assertIn("/api/health", login_path.read_text(encoding="utf-8"))
            self.assertIn("/api/me", login_path.read_text(encoding="utf-8"))

    def test_stage_all_stages_untracked_files(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            subprocess.run(["git", "init"], cwd=repo_dir, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True)
            Path(repo_dir, "new-file.txt").write_text("hello", encoding="utf-8")
            self.assertEqual(_stage_all(repo_dir), 0)
            subprocess.run(["git", "commit", "-m", "test"], cwd=repo_dir, check=True)
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=repo_dir,
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
            self.assertEqual(status, "")

    def test_ems_api_jwt_decode(self):
        work_item = {
            "id": "ems-api-scaffold",
            "repo_targets": [
                {
                    "name": "xyn-api",
                    "url": "https://example.com/xyn-api",
                    "ref": "main",
                    "path_root": "apps/ems-api",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            _apply_scaffold_for_work_item(work_item, repo_dir)
            ems_root = Path(repo_dir, "apps/ems-api")
            self.assertTrue((ems_root / "ems_api").exists())
            sys.path.insert(0, str(ems_root))
            import importlib  # noqa: WPS433
            importlib.invalidate_caches()
            for key in list(sys.modules.keys()):
                if key.startswith("ems_api"):
                    del sys.modules[key]
            os.environ["EMS_JWT_SECRET"] = "test-secret"
            os.environ["EMS_JWT_ISSUER"] = "xyn-ems"
            os.environ["EMS_JWT_AUDIENCE"] = "ems"
            import jwt  # noqa: WPS433
            decode_token = importlib.import_module("ems_api.auth").decode_token  # noqa: WPS433

            token = jwt.encode(
                {
                    "iss": "xyn-ems",
                    "aud": "ems",
                    "sub": "dev-user",
                    "email": "dev@example.com",
                },
                "test-secret",
                algorithm="HS256",
            )
            claims = decode_token(token)
            self.assertEqual(claims["sub"], "dev-user")

    def test_devices_rbac(self):
        scaffold = {
            "id": "ems-api-scaffold",
            "repo_targets": [
                {
                    "name": "xyn-api",
                    "url": "https://example.com/xyn-api",
                    "ref": "main",
                    "path_root": "apps/ems-api",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        devices_rbac = {
            "id": "ems-api-devices-rbac",
            "repo_targets": [
                {
                    "name": "xyn-api",
                    "url": "https://example.com/xyn-api",
                    "ref": "main",
                    "path_root": "apps/ems-api",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            _apply_scaffold_for_work_item(scaffold, repo_dir)
            _apply_scaffold_for_work_item(devices_rbac, repo_dir)
            ems_root = Path(repo_dir, "apps/ems-api")
            self.assertTrue((ems_root / "ems_api").exists())
            sys.path.insert(0, str(ems_root))
            import importlib  # noqa: WPS433
            importlib.invalidate_caches()
            for key in list(sys.modules.keys()):
                if key.startswith("ems_api"):
                    del sys.modules[key]
            os.environ["EMS_JWT_SECRET"] = "test-secret"
            os.environ["EMS_JWT_ISSUER"] = "xyn-ems"
            os.environ["EMS_JWT_AUDIENCE"] = "ems"
            from fastapi import HTTPException  # noqa: WPS433
            from ems_api.rbac import require_roles  # noqa: WPS433

            viewer_user = {"roles": ["viewer"]}
            admin_user = {"roles": ["admin"]}
            require_admin = require_roles("admin")
            with self.assertRaises(HTTPException) as ctx:
                require_admin(user=viewer_user)
            self.assertEqual(ctx.exception.status_code, 403)
            self.assertEqual(require_admin(user=admin_user), admin_user)

    def test_devices_sqlite_persistence(self):
        try:
            import sqlalchemy  # noqa: F401,WPS433
        except ImportError:
            self.skipTest("sqlalchemy not installed")
        scaffold = {
            "id": "ems-api-scaffold",
            "repo_targets": [
                {
                    "name": "xyn-api",
                    "url": "https://example.com/xyn-api",
                    "ref": "main",
                    "path_root": "apps/ems-api",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        db_foundation = {
            "id": "ems-api-db-foundation",
            "repo_targets": [
                {
                    "name": "xyn-api",
                    "url": "https://example.com/xyn-api",
                    "ref": "main",
                    "path_root": "apps/ems-api",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        devices_postgres = {
            "id": "ems-api-devices-postgres",
            "repo_targets": [
                {
                    "name": "xyn-api",
                    "url": "https://example.com/xyn-api",
                    "ref": "main",
                    "path_root": "apps/ems-api",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            _apply_scaffold_for_work_item(scaffold, repo_dir)
            _apply_scaffold_for_work_item(db_foundation, repo_dir)
            _apply_scaffold_for_work_item(devices_postgres, repo_dir)
            ems_root = Path(repo_dir, "apps/ems-api")
            sys.path.insert(0, str(ems_root))
            import importlib  # noqa: WPS433
            importlib.invalidate_caches()
            for key in list(sys.modules.keys()):
                if key.startswith("ems_api"):
                    del sys.modules[key]
            os.environ["DATABASE_URL"] = f"sqlite:///{Path(repo_dir, 'devices.db')}"
            db_module = importlib.import_module("ems_api.db")
            models_module = importlib.import_module("ems_api.models")
            models_module.Base.metadata.create_all(bind=db_module.engine)
            session = db_module.SessionLocal()
            try:
                device = models_module.Device(name="persist1")
                session.add(device)
                session.commit()
                session.refresh(device)
                result = session.query(models_module.Device).all()
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0].name, "persist1")
            finally:
                session.close()

    def test_api_scaffold_writes_dockerfile(self):
        work_item = {
            "id": "ems-api-scaffold",
            "repo_targets": [
                {
                    "name": "xyn-api",
                    "url": "https://example.com/xyn-api",
                    "ref": "main",
                    "path_root": "apps/ems-api",
                    "auth": "local",
                    "allow_write": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as repo_dir:
            _apply_scaffold_for_work_item(work_item, repo_dir)
            dockerfile = Path(repo_dir, "apps/ems-api/Dockerfile")
            self.assertTrue(dockerfile.exists())

    def test_legacy_work_item_capabilities_fallback(self):
        work_item = {"id": "remote-deploy-compose-ssm"}
        caps = _work_item_capabilities(work_item, "remote-deploy-compose-ssm")
        self.assertIn("runtime.compose.apply_remote", caps)
        self.assertIn("deploy.ssm.run_shell", caps)
