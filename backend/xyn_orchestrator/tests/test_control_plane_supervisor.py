import json
import os
import tempfile
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from xyn_orchestrator.deployments import maybe_trigger_rollback
from xyn_orchestrator.models import (
    Deployment,
    Environment,
    EnvironmentAppState,
    ProvisionedInstance,
    Release,
    ReleasePlan,
    RoleBinding,
    Run,
    RunArtifact,
    UserIdentity,
)


class ControlPlaneSupervisorTests(TestCase):
    def _seed_plan_artifact(self, run: Run, media_root: str, payload: dict | None = None) -> str:
        artifact_dir = os.path.join(media_root, "run_artifacts", str(run.id))
        os.makedirs(artifact_dir, exist_ok=True)
        path = os.path.join(artifact_dir, "release_plan.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload or {"steps": [{"name": "noop", "commands": ["echo ok"]}]}, handle)
        return f"/media/run_artifacts/{run.id}/release_plan.json"

    def _seed_identity(self, role: str) -> None:
        user = get_user_model().objects.create_user(username=f"u-{role}", password="x", is_staff=True)
        self.client.force_login(user)
        identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer", subject=f"sub-{role}")
        RoleBinding.objects.create(user_identity=identity, scope_kind="platform", role=role)
        session = self.client.session
        session["user_identity_id"] = str(identity.id)
        session.save()

    @override_settings(MEDIA_URL="/media/")
    def test_control_plane_deploy_denies_non_architect(self):
        with tempfile.TemporaryDirectory() as tmpdir, override_settings(MEDIA_ROOT=tmpdir):
            self._seed_identity("platform_operator")
            env = Environment.objects.create(name="dev", slug="dev")
            plan = ReleasePlan.objects.create(
                name="xyn api",
                target_kind="blueprint",
                target_fqn="xyn-api",
                to_version="v1",
                environment=env,
            )
            run = Run.objects.create(entity_type="release_plan", entity_id=plan.id)
            plan.last_run = run
            plan.save(update_fields=["last_run"])
            url = self._seed_plan_artifact(run, tmpdir)
            RunArtifact.objects.create(run=run, name="release_plan.json", url=url)
            release = Release.objects.create(version="v1", status="published", build_state="ready", release_plan=plan)
            instance = ProvisionedInstance.objects.create(
                name="xyence-1",
                environment=env,
                aws_region="us-west-2",
                instance_id="i-123",
                instance_type="t3.small",
                ami_id="ami-123",
            )
            response = self.client.post(
                "/xyn/api/control-plane/deploy",
                data=json.dumps(
                    {
                        "environment_id": str(env.id),
                        "app_id": "xyn-api",
                        "release_id": str(release.id),
                        "instance_id": str(instance.id),
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(response.status_code, 403)

    @override_settings(MEDIA_URL="/media/")
    def test_control_plane_deploy_allows_architect(self):
        with tempfile.TemporaryDirectory() as tmpdir, override_settings(MEDIA_ROOT=tmpdir):
            self._seed_identity("platform_architect")
            env = Environment.objects.create(name="dev", slug="dev")
            plan = ReleasePlan.objects.create(
                name="xyn api",
                target_kind="blueprint",
                target_fqn="xyn-api",
                to_version="v1",
                environment=env,
            )
            run = Run.objects.create(entity_type="release_plan", entity_id=plan.id)
            plan.last_run = run
            plan.save(update_fields=["last_run"])
            url = self._seed_plan_artifact(run, tmpdir)
            RunArtifact.objects.create(run=run, name="release_plan.json", url=url)
            release = Release.objects.create(version="v1", status="published", build_state="ready", release_plan=plan)
            instance = ProvisionedInstance.objects.create(
                name="xyence-1",
                environment=env,
                aws_region="us-west-2",
                instance_id="i-123",
                instance_type="t3.small",
                ami_id="ami-123",
            )

            def _fake_exec(dep, *_args, **_kwargs):
                dep.status = "succeeded"
                dep.health_check_status = "passed"
                dep.started_at = timezone.now()
                dep.finished_at = timezone.now()
                dep.save(update_fields=["status", "health_check_status", "started_at", "finished_at", "updated_at"])
                EnvironmentAppState.objects.update_or_create(
                    environment=env,
                    app_id="xyn-api",
                    defaults={"current_release": release, "last_good_release": release, "last_good_at": timezone.now()},
                )

            with mock.patch("xyn_orchestrator.xyn_api.execute_release_plan_deploy", side_effect=_fake_exec):
                response = self.client.post(
                    "/xyn/api/control-plane/deploy",
                    data=json.dumps(
                        {
                            "environment_id": str(env.id),
                            "app_id": "xyn-api",
                            "release_id": str(release.id),
                            "instance_id": str(instance.id),
                        }
                    ),
                    content_type="application/json",
                )
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload.get("status"), "succeeded")

    @override_settings(MEDIA_URL="/media/")
    def test_maybe_trigger_rollback_uses_last_good_release(self):
        with tempfile.TemporaryDirectory() as tmpdir, override_settings(MEDIA_ROOT=tmpdir):
            env = Environment.objects.create(name="dev", slug="dev")
            plan = ReleasePlan.objects.create(
                name="xyn api",
                target_kind="blueprint",
                target_fqn="xyn-api",
                to_version="v2",
                environment=env,
            )
            run = Run.objects.create(entity_type="release_plan", entity_id=plan.id)
            plan.last_run = run
            plan.save(update_fields=["last_run"])
            url = self._seed_plan_artifact(run, tmpdir, payload={"steps": []})
            RunArtifact.objects.create(run=run, name="release_plan.json", url=url)
            bad_release = Release.objects.create(version="v2", status="published", build_state="ready", release_plan=plan)
            good_release = Release.objects.create(version="v1", status="published", build_state="ready", release_plan=plan)
            instance = ProvisionedInstance.objects.create(
                name="xyence-1",
                environment=env,
                aws_region="us-west-2",
                instance_id="i-123",
                instance_type="t3.small",
                ami_id="ami-123",
            )
            failed = Deployment.objects.create(
                idempotency_key="k1",
                idempotency_base="b1",
                app_id="xyn-api",
                environment=env,
                release=bad_release,
                instance=instance,
                release_plan=plan,
                deploy_kind="release_plan",
                status="failed",
            )
            EnvironmentAppState.objects.create(
                environment=env,
                app_id="xyn-api",
                current_release=bad_release,
                last_good_release=good_release,
            )

            def _fake_exec(dep, *_args, **_kwargs):
                dep.status = "succeeded"
                dep.started_at = timezone.now()
                dep.finished_at = timezone.now()
                dep.save(update_fields=["status", "started_at", "finished_at", "updated_at"])

            with mock.patch("xyn_orchestrator.deployments.execute_release_plan_deploy", side_effect=_fake_exec):
                rollback = maybe_trigger_rollback(failed)

            self.assertIsNotNone(rollback)
            assert rollback is not None
            self.assertEqual(str(rollback.rollback_of_id), str(failed.id))
            self.assertEqual(str(rollback.release_id), str(good_release.id))

    def test_maybe_trigger_rollback_returns_none_without_last_good(self):
        env = Environment.objects.create(name="dev", slug="dev")
        plan = ReleasePlan.objects.create(name="xyn api", target_kind="blueprint", target_fqn="xyn-api", to_version="v2", environment=env)
        release = Release.objects.create(version="v2", status="published", build_state="ready", release_plan=plan)
        instance = ProvisionedInstance.objects.create(
            name="xyence-1",
            environment=env,
            aws_region="us-west-2",
            instance_id="i-123",
            instance_type="t3.small",
            ami_id="ami-123",
        )
        failed = Deployment.objects.create(
            idempotency_key="k2",
            idempotency_base="b2",
            app_id="xyn-api",
            environment=env,
            release=release,
            instance=instance,
            release_plan=plan,
            deploy_kind="release_plan",
            status="failed",
        )
        self.assertIsNone(maybe_trigger_rollback(failed))
