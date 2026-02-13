from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import (
    Blueprint,
    Environment,
    ProvisionedInstance,
    Release,
    ReleasePlan,
    ReleaseTarget,
    RoleBinding,
    Run,
    Tenant,
    TenantMembership,
    UserIdentity,
)


class MapApiTests(TestCase):
    def _login_with_identity(self, identity: UserIdentity, is_staff: bool = False):
        User = get_user_model()
        user = User.objects.create_user(
            username=f"user-{identity.subject}",
            email=identity.email or "",
            password="x",
            is_staff=is_staff,
            is_active=True,
        )
        self.client.force_login(user)
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()

    def test_map_requires_auth(self):
        response = self.client.get("/xyn/api/map")
        self.assertIn(response.status_code, {302, 401})

    def test_map_scopes_non_admin_to_memberships(self):
        tenant_a = Tenant.objects.create(name="Tenant A", slug="tenant-a")
        tenant_b = Tenant.objects.create(name="Tenant B", slug="tenant-b")
        allowed_blueprint = Blueprint.objects.create(
            name="allowed-app",
            namespace="tenant",
            metadata_json={"tenant_id": str(tenant_a.id)},
        )
        Blueprint.objects.create(
            name="blocked-app",
            namespace="tenant",
            metadata_json={"tenant_id": str(tenant_b.id)},
        )
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="member-1",
            email="member@xyence.io",
        )
        TenantMembership.objects.create(
            tenant=tenant_a,
            user_identity=identity,
            role="tenant_viewer",
            status="active",
        )
        self._login_with_identity(identity, is_staff=False)
        response = self.client.get("/xyn/api/map")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        blueprint_nodes = [node for node in payload.get("nodes", []) if node.get("kind") == "blueprint"]
        node_ids = {node.get("ref", {}).get("id") for node in blueprint_nodes}
        self.assertIn(str(allowed_blueprint.id), node_ids)
        self.assertEqual(len(node_ids), 1)

    def test_map_includes_release_target_enrichment_fields(self):
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="admin-1",
            email="admin@xyence.io",
        )
        RoleBinding.objects.create(user_identity=identity, scope_kind="platform", role="platform_admin")
        self._login_with_identity(identity, is_staff=True)

        blueprint = Blueprint.objects.create(name="xyn-api", namespace="core")
        environment = Environment.objects.create(name="Prod", slug="prod")
        release_plan = ReleasePlan.objects.create(
            name="prod-plan",
            target_kind="blueprint",
            target_fqn="core.xyn-api",
            to_version="1.0.0",
            blueprint=blueprint,
            environment=environment,
        )
        build_run = Run.objects.create(
            entity_type="release_plan",
            entity_id=release_plan.id,
            status="succeeded",
            summary="Build release",
        )
        release = Release.objects.create(
            blueprint=blueprint,
            version="1.0.0",
            release_plan=release_plan,
            created_from_run=build_run,
            status="published",
            build_state="ready",
        )
        instance = ProvisionedInstance.objects.create(
            name="prod-1",
            environment=environment,
            aws_region="us-east-1",
            instance_type="t3.medium",
            ami_id="ami-123",
            status="running",
        )
        target = ReleaseTarget.objects.create(
            blueprint=blueprint,
            name="prod-target",
            environment="prod",
            target_instance=instance,
            target_instance_ref=str(instance.id),
            fqdn="api.xyence.io",
            config_json={"id": "prod-target", "tenant_id": "ignored-for-admin"},
        )
        Run.objects.create(
            entity_type="blueprint",
            entity_id=blueprint.id,
            status="succeeded",
            summary="Deploy latest",
            metadata_json={
                "release_target_id": str(target.id),
                "release_uuid": str(release.id),
                "release_version": release.version,
                "deploy_outcome": "succeeded",
            },
        )

        response = self.client.get("/xyn/api/map")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        target_node = next(node for node in payload.get("nodes", []) if node.get("id") == f"release_target:{target.id}")
        metrics = target_node.get("metrics", {})
        self.assertIn("current_release_id", metrics)
        self.assertIn("current_release_version", metrics)
        self.assertIn("drift_state", metrics)
        self.assertIn("lock_state", metrics)
        self.assertIn("last_deploy_outcome", metrics)
        self.assertIn("last_deploy_at", metrics)

    def test_map_excludes_draft_releases_by_default(self):
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="admin-2",
            email="admin2@xyence.io",
        )
        RoleBinding.objects.create(user_identity=identity, scope_kind="platform", role="platform_admin")
        self._login_with_identity(identity, is_staff=True)
        blueprint = Blueprint.objects.create(name="xyn-ui", namespace="core")
        Release.objects.create(blueprint=blueprint, version="v49", status="published", build_state="ready")
        draft = Release.objects.create(blueprint=blueprint, version="v50", status="draft", build_state="draft")

        response = self.client.get("/xyn/api/map")
        self.assertEqual(response.status_code, 200)
        node_ids = {node.get("id") for node in response.json().get("nodes", [])}
        self.assertNotIn(f"release:{draft.id}", node_ids)


class ReleaseDeleteTests(TestCase):
    def _login_admin(self):
        identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="admin-delete",
            email="admin-delete@xyence.io",
        )
        RoleBinding.objects.create(user_identity=identity, scope_kind="platform", role="platform_admin")
        User = get_user_model()
        user = User.objects.create_user(
            username="admin-delete@xyence.io",
            email="admin-delete@xyence.io",
            password="x",
            is_staff=True,
            is_active=True,
        )
        self.client.force_login(user)
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()

    def test_delete_published_release_with_plan_denied(self):
        self._login_admin()
        blueprint = Blueprint.objects.create(name="xyn-api", namespace="core")
        env = Environment.objects.create(name="Prod", slug="prod-del")
        plan = ReleasePlan.objects.create(
            name="plan",
            target_kind="blueprint",
            target_fqn="core.xyn-api",
            to_version="1.0.0",
            blueprint=blueprint,
            environment=env,
        )
        release = Release.objects.create(
            blueprint=blueprint,
            version="v1",
            status="published",
            build_state="ready",
            release_plan=plan,
        )
        response = self.client.delete(f"/xyn/api/releases/{release.id}")
        self.assertEqual(response.status_code, 400)

    def test_delete_draft_release_allowed(self):
        self._login_admin()
        blueprint = Blueprint.objects.create(name="xyn-ui", namespace="core")
        release = Release.objects.create(
            blueprint=blueprint,
            version="v2",
            status="draft",
            build_state="draft",
        )
        response = self.client.delete(f"/xyn/api/releases/{release.id}")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Release.objects.filter(id=release.id).exists())

    def test_bulk_delete_mixed_results(self):
        self._login_admin()
        blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
        env = Environment.objects.create(name="Prod", slug="prod-bulk")
        plan = ReleasePlan.objects.create(
            name="plan-bulk",
            target_kind="blueprint",
            target_fqn="core.ems.platform",
            to_version="1.0.0",
            blueprint=blueprint,
            environment=env,
        )
        deletable_draft = Release.objects.create(
            blueprint=blueprint,
            version="v901",
            status="draft",
            build_state="draft",
        )
        deletable_published = Release.objects.create(
            blueprint=blueprint,
            version="v902",
            status="published",
            build_state="ready",
        )
        protected_published = Release.objects.create(
            blueprint=blueprint,
            version="v903",
            status="published",
            build_state="ready",
            release_plan=plan,
        )

        response = self.client.post(
            "/xyn/api/releases/bulk-delete",
            data={
                "release_ids": [
                    str(deletable_draft.id),
                    str(deletable_published.id),
                    str(protected_published.id),
                    "11111111-1111-1111-1111-111111111111",
                ]
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 207)
        payload = response.json()
        self.assertEqual(payload.get("deleted_count"), 2)
        self.assertEqual(payload.get("skipped_count"), 2)
        self.assertFalse(Release.objects.filter(id=deletable_draft.id).exists())
        self.assertFalse(Release.objects.filter(id=deletable_published.id).exists())
        self.assertTrue(Release.objects.filter(id=protected_published.id).exists())
