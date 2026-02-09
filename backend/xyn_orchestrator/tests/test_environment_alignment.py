import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import AuditLog, Deployment, Environment, ProvisionedInstance, Release, ReleasePlan


class EnvironmentAlignmentTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username="staff",
            email="staff@example.com",
            password="pass",
            is_staff=True,
        )
        self.client.force_login(self.user)

    def test_release_api_has_no_environment(self):
        release = Release.objects.create(version="v1", status="published")
        response = self.client.get("/xyn/api/releases")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("releases", payload)
        self.assertNotIn("environment_id", payload["releases"][0])
        response = self.client.get(f"/xyn/api/releases/{release.id}")
        self.assertEqual(response.status_code, 200)
        detail = response.json()
        self.assertNotIn("environment_id", detail)

    def test_instance_environment_update_validation_and_audit(self):
        env_a = Environment.objects.create(name="prod")
        env_b = Environment.objects.create(name="staging")
        release = Release.objects.create(version="v1", status="published")
        instance = ProvisionedInstance.objects.create(
            name="i-1",
            environment=env_a,
            aws_region="us-west-2",
            instance_id="i-123",
            instance_type="t3",
            ami_id="ami-123",
        )
        Deployment.objects.create(
            idempotency_key="key-1",
            idempotency_base="base-1",
            release=release,
            instance=instance,
            status="running",
        )
        response = self.client.patch(
            f"/xyn/api/provision/instances/{instance.id}",
            data=json.dumps({"environment_id": str(env_b.id)}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 409)
        response = self.client.patch(
            f"/xyn/api/provision/instances/{instance.id}",
            data=json.dumps({"environment_id": str(env_b.id), "force": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        instance.refresh_from_db()
        self.assertEqual(instance.environment_id, env_b.id)
        self.assertEqual(AuditLog.objects.count(), 1)

    def test_release_plan_requires_environment(self):
        payload = {
            "name": "Plan",
            "target_kind": "blueprint",
            "target_fqn": "core.ems.platform",
            "to_version": "0.1.0",
        }
        response = self.client.post(
            "/xyn/api/release-plans",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_release_filter_published(self):
        Release.objects.create(version="v1", status="published")
        Release.objects.create(version="v2", status="draft")
        response = self.client.get("/xyn/api/releases?status=published")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["releases"]), 1)
        self.assertEqual(payload["releases"][0]["status"], "published")

    def test_release_plan_deployment_environment_mismatch(self):
        env_a = Environment.objects.create(name="prod")
        env_b = Environment.objects.create(name="staging")
        plan = ReleasePlan.objects.create(
            name="Plan",
            target_kind="blueprint",
            target_fqn="core.ems.platform",
            from_version="",
            to_version="0.1.0",
            environment=env_a,
        )
        instance = ProvisionedInstance.objects.create(
            name="i-1",
            environment=env_b,
            aws_region="us-west-2",
            instance_id="i-123",
            instance_type="t3",
            ami_id="ami-123",
        )
        response = self.client.post(
            f"/xyn/api/release-plans/{plan.id}/deployments",
            data=json.dumps({"instance_id": str(instance.id)}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
