import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import Blueprint, Environment, Release, ReleasePlan


class ReleasePlanAlignmentTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="staff", password="pass", is_staff=True)
        self.client.force_login(user)
        self.blueprint = Blueprint.objects.create(name="ems", namespace="core", description="")
        self.environment = Environment.objects.create(name="Dev", slug="dev")

    def test_releases_collection_resolves_plan_by_to_version_when_link_is_stale(self):
        plan = ReleasePlan.objects.create(
            name="Release plan for core.ems.platform",
            target_kind="blueprint",
            target_fqn="core.ems.platform",
            from_version="v44",
            to_version="v45",
            blueprint=self.blueprint,
            environment=self.environment,
        )
        stale = Release.objects.create(
            blueprint=self.blueprint,
            version="v40",
            status="published",
            build_state="ready",
            release_plan=plan,
        )
        current = Release.objects.create(
            blueprint=self.blueprint,
            version="v45",
            status="published",
            build_state="ready",
        )

        response = self.client.get("/xyn/api/releases")
        self.assertEqual(response.status_code, 200)
        rows = {entry["id"]: entry for entry in response.json()["releases"]}
        self.assertEqual(rows[str(current.id)]["release_plan_id"], str(plan.id))
        self.assertIsNone(rows[str(stale.id)]["release_plan_id"])

    def test_release_plan_patch_relinks_selected_release(self):
        plan = ReleasePlan.objects.create(
            name="Release plan for core.ems.platform",
            target_kind="blueprint",
            target_fqn="core.ems.platform",
            from_version="v44",
            to_version="v40",
            blueprint=self.blueprint,
            environment=self.environment,
        )
        old_release = Release.objects.create(
            blueprint=self.blueprint,
            version="v40",
            status="published",
            build_state="ready",
            release_plan=plan,
        )
        new_release = Release.objects.create(
            blueprint=self.blueprint,
            version="v45",
            status="published",
            build_state="ready",
        )

        response = self.client.patch(
            f"/xyn/api/release-plans/{plan.id}",
            data=json.dumps({"to_version": "v45", "selected_release_id": str(new_release.id)}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)

        old_release.refresh_from_db()
        new_release.refresh_from_db()
        self.assertIsNone(old_release.release_plan_id)
        self.assertEqual(str(new_release.release_plan_id), str(plan.id))
