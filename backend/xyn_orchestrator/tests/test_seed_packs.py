import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import ContextPack, RoleBinding, UserIdentity
from xyn_orchestrator.seeds import apply_seed_packs, list_seed_packs_status


class SeedPackTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username="seed-admin", password="pass", is_staff=True)
        self.client.force_login(self.user)
        self.admin_identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer",
            subject="seed-admin",
            email="seed-admin@example.com",
        )
        self.reader_identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer",
            subject="seed-reader",
            email="seed-reader@example.com",
        )
        RoleBinding.objects.create(user_identity=self.admin_identity, scope_kind="platform", role="platform_admin")
        RoleBinding.objects.create(user_identity=self.reader_identity, scope_kind="platform", role="app_user")

    def _set_identity(self, identity: UserIdentity):
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()

    def test_apply_core_seeds_creates_missing_context_packs(self):
        ContextPack.objects.filter(name="xyn-platform-canon", scope="global").delete()
        ContextPack.objects.filter(name="xyn-console-default", scope="global").delete()
        result = apply_seed_packs(apply_core=True)
        self.assertGreaterEqual(result["summary"].get("created", 0), 1)
        self.assertTrue(ContextPack.objects.filter(name="xyn-platform-canon", scope="global").exists())
        self.assertTrue(ContextPack.objects.filter(name="xyn-console-default", scope="global").exists())

    def test_reapply_core_seeds_is_idempotent(self):
        first = apply_seed_packs(apply_core=True)
        second = apply_seed_packs(apply_core=True)
        self.assertGreaterEqual(first["summary"].get("created", 0) + first["summary"].get("updated", 0), 1)
        self.assertEqual(second["summary"].get("created", 0), 0)
        self.assertEqual(second["summary"].get("updated", 0), 0)
        self.assertGreaterEqual(second["summary"].get("unchanged", 0), 1)

    def test_optional_pack_not_auto_applied_by_core(self):
        apply_seed_packs(apply_core=True)
        self.assertFalse(
            ContextPack.objects.filter(name="xyence-engineering-conventions", scope="namespace", namespace="xyence").exists()
        )

    def test_drift_detection_marks_drifted_records(self):
        apply_seed_packs(apply_core=True)
        pack = ContextPack.objects.filter(name="xyn-planner-canon", scope="global").first()
        assert pack is not None
        pack.content_markdown = (pack.content_markdown or "") + "\n\n# local drift"
        pack.save(update_fields=["content_markdown", "updated_at"])

        rows = list_seed_packs_status(include_items=True)
        core = next(row for row in rows if row["slug"] == "xyn-core-context-packs")
        self.assertGreaterEqual(int(core["drifted_count"]), 1)

    def test_seed_endpoints_require_admin_and_support_apply(self):
        self._set_identity(self.reader_identity)
        denied = self.client.get("/xyn/api/seeds/packs")
        self.assertEqual(denied.status_code, 403)

        self._set_identity(self.admin_identity)
        listing = self.client.get("/xyn/api/seeds/packs")
        self.assertEqual(listing.status_code, 200)
        self.assertTrue(listing.json().get("packs"))

        apply_response = self.client.post(
            "/xyn/api/seeds/apply",
            data=json.dumps({"apply_core": True, "dry_run": True}),
            content_type="application/json",
        )
        self.assertEqual(apply_response.status_code, 200)
        payload = apply_response.json()
        self.assertTrue(payload.get("dry_run"))
        self.assertIn("summary", payload)
