import json
import os
import tempfile
from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from xyn_orchestrator.models import Deployment, ProvisionedInstance, Release, ReleasePlan, Run, RunArtifact


class InternalDeploymentsTests(TestCase):
    def _seed_plan_artifact(self, run: Run, media_root: str) -> str:
        artifact_dir = os.path.join(media_root, "run_artifacts", str(run.id))
        os.makedirs(artifact_dir, exist_ok=True)
        path = os.path.join(artifact_dir, "release_plan.json")
        payload = {"steps": [{"name": "noop", "commands": ["echo ok"]}]}
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        return f"/media/run_artifacts/{run.id}/release_plan.json"

    @override_settings(MEDIA_URL="/media/")
    def test_auth_required(self):
        os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
        response = self.client.post("/xyn/internal/deployments", data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 401)

    @override_settings(MEDIA_URL="/media/")
    def test_idempotency_and_force(self):
        with tempfile.TemporaryDirectory() as tmpdir, override_settings(MEDIA_ROOT=tmpdir):
            os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
            release_plan = ReleasePlan.objects.create(
                name="Plan",
                target_kind="blueprint",
                target_fqn="core.ems.platform",
                from_version="",
                to_version="0.1.0",
            )
            run = Run.objects.create(entity_type="release_plan", entity_id=release_plan.id)
            release_plan.last_run = run
            release_plan.save(update_fields=["last_run"])
            url = self._seed_plan_artifact(run, tmpdir)
            RunArtifact.objects.create(run=run, name="release_plan.json", url=url)
            release = Release.objects.create(
                version="v1",
                status="published",
                release_plan=release_plan,
                artifacts_json={"release_plan": {"url": url}},
            )
            instance = ProvisionedInstance.objects.create(
                name="i-1",
                environment=None,
                aws_region="us-west-2",
                instance_id="i-123",
                instance_type="t3",
                ami_id="ami-123",
            )

            def _fake_exec(dep, *_args, **_kwargs):
                dep.status = "succeeded"
                dep.started_at = timezone.now()
                dep.finished_at = timezone.now()
                dep.save(update_fields=["status", "started_at", "finished_at", "updated_at"])
                return {}

            with mock.patch("xyn_orchestrator.blueprints.execute_release_plan_deploy", side_effect=_fake_exec):
                payload = {
                    "release_id": str(release.id),
                    "instance_id": str(instance.id),
                    "release_plan_id": str(release_plan.id),
                }
                response = self.client.post(
                    "/xyn/internal/deployments",
                    data=json.dumps(payload),
                    content_type="application/json",
                    HTTP_X_INTERNAL_TOKEN="test-token",
                )
                self.assertEqual(response.status_code, 200)
                first = response.json()
                response = self.client.post(
                    "/xyn/internal/deployments",
                    data=json.dumps(payload),
                    content_type="application/json",
                    HTTP_X_INTERNAL_TOKEN="test-token",
                )
                second = response.json()
                self.assertTrue(second.get("existing"))
                self.assertEqual(first["deployment_id"], second["deployment_id"])
                payload["force"] = True
                response = self.client.post(
                    "/xyn/internal/deployments",
                    data=json.dumps(payload),
                    content_type="application/json",
                    HTTP_X_INTERNAL_TOKEN="test-token",
                )
                third = response.json()
                self.assertFalse(third.get("existing"))
                self.assertNotEqual(first["deployment_id"], third["deployment_id"])
                self.assertEqual(Deployment.objects.count(), 2)

    @override_settings(MEDIA_URL="/media/")
    def test_draft_gating(self):
        with tempfile.TemporaryDirectory() as tmpdir, override_settings(MEDIA_ROOT=tmpdir):
            os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
            release_plan = ReleasePlan.objects.create(
                name="Plan",
                target_kind="blueprint",
                target_fqn="core.ems.platform",
                from_version="",
                to_version="0.1.0",
            )
            run = Run.objects.create(entity_type="release_plan", entity_id=release_plan.id)
            release_plan.last_run = run
            release_plan.save(update_fields=["last_run"])
            url = self._seed_plan_artifact(run, tmpdir)
            RunArtifact.objects.create(run=run, name="release_plan.json", url=url)
            release = Release.objects.create(
                version="v1",
                status="draft",
                release_plan=release_plan,
                artifacts_json={"release_plan": {"url": url}},
            )
            instance = ProvisionedInstance.objects.create(
                name="i-1",
                environment=None,
                aws_region="us-west-2",
                instance_id="i-123",
                instance_type="t3",
                ami_id="ami-123",
            )
            payload = {
                "release_id": str(release.id),
                "instance_id": str(instance.id),
                "release_plan_id": str(release_plan.id),
            }
            response = self.client.post(
                "/xyn/internal/deployments",
                data=json.dumps(payload),
                content_type="application/json",
                HTTP_X_INTERNAL_TOKEN="test-token",
            )
            self.assertEqual(response.status_code, 400)
            payload["allow_draft"] = True
            with mock.patch("xyn_orchestrator.blueprints.execute_release_plan_deploy") as exec_mock:
                exec_mock.side_effect = lambda dep, *_args, **_kwargs: dep
                response = self.client.post(
                    "/xyn/internal/deployments",
                    data=json.dumps(payload),
                    content_type="application/json",
                    HTTP_X_INTERNAL_TOKEN="test-token",
                )
                self.assertEqual(response.status_code, 200)

    @override_settings(MEDIA_URL="/media/")
    def test_failed_execution_sets_status(self):
        with tempfile.TemporaryDirectory() as tmpdir, override_settings(MEDIA_ROOT=tmpdir):
            os.environ["XYENCE_INTERNAL_TOKEN"] = "test-token"
            release_plan = ReleasePlan.objects.create(
                name="Plan",
                target_kind="blueprint",
                target_fqn="core.ems.platform",
                from_version="",
                to_version="0.1.0",
            )
            run = Run.objects.create(entity_type="release_plan", entity_id=release_plan.id)
            release_plan.last_run = run
            release_plan.save(update_fields=["last_run"])
            url = self._seed_plan_artifact(run, tmpdir)
            RunArtifact.objects.create(run=run, name="release_plan.json", url=url)
            release = Release.objects.create(
                version="v1",
                status="published",
                release_plan=release_plan,
                artifacts_json={"release_plan": {"url": url}},
            )
            instance = ProvisionedInstance.objects.create(
                name="i-1",
                environment=None,
                aws_region="us-west-2",
                instance_id="i-123",
                instance_type="t3",
                ami_id="ami-123",
            )

            def _fail_exec(dep, *_args, **_kwargs):
                dep.status = "failed"
                dep.error_message = "boom"
                dep.finished_at = timezone.now()
                dep.save(update_fields=["status", "error_message", "finished_at", "updated_at"])
                return {}

            with mock.patch("xyn_orchestrator.blueprints.execute_release_plan_deploy", side_effect=_fail_exec):
                payload = {
                    "release_id": str(release.id),
                    "instance_id": str(instance.id),
                    "release_plan_id": str(release_plan.id),
                }
                response = self.client.post(
                    "/xyn/internal/deployments",
                    data=json.dumps(payload),
                    content_type="application/json",
                    HTTP_X_INTERNAL_TOKEN="test-token",
                )
                data = response.json()
                self.assertEqual(data["status"], "failed")
                self.assertEqual(data["error_message"], "boom")
