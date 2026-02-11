import tempfile
from unittest import mock

from django.test import TestCase, override_settings

from xyn_orchestrator.deployments import _extract_tls_error_code, _lower_plan_steps, execute_release_plan_deploy
from xyn_orchestrator.models import Blueprint, Deployment, ProvisionedInstance, Release, ReleasePlan, ReleaseTarget


class DeploymentTlsTests(TestCase):
    def _ssm_result(self, status: str = "Success", code: int = 0, stdout: str = "", stderr: str = ""):
        return {
            "ssm_command_id": "cmd-1",
            "invocation_status": status,
            "response_code": code,
            "stdout": stdout,
            "stderr": stderr,
            "started_at": "2026-02-11T00:00:00Z",
            "finished_at": "2026-02-11T00:00:01Z",
        }

    def test_lowering_adds_tls_steps_from_tasks(self):
        plan = {
            "steps": [{"name": "prepare", "commands": ["echo ok"]}],
            "tasks": [{"id": "tls.acme_http01"}, {"id": "verify.public_https"}],
        }
        lowered = _lower_plan_steps(plan, None)
        names = [item.get("name") for item in lowered]
        self.assertIn("prepare", names)
        self.assertIn("tls_acme_http01_issue", names)
        self.assertIn("ingress_nginx_tls_configure", names)
        self.assertIn("verify_public_https", names)

    def test_extract_tls_error_code_maps_acme_connection_refused(self):
        stderr = (
            "Could not obtain certificates:\n"
            "error: one or more domains had a problem:\n"
            "[ems.xyence.io] acme: error: 400 :: urn:ietf:params:acme:error:connection :: "
            "44.251.235.187: Fetching http://ems.xyence.io/.well-known/acme-challenge/token: Connection refused\n"
        )
        self.assertEqual(_extract_tls_error_code(stderr), "acme_http01_connection_refused")

    @override_settings(MEDIA_URL="/media/")
    def test_deploy_fails_when_tls_verify_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir, override_settings(MEDIA_ROOT=tmpdir):
            blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
            plan = ReleasePlan.objects.create(
                name="Plan",
                target_kind="blueprint",
                target_fqn="core.ems.platform",
                from_version="",
                to_version="v40",
            )
            instance = ProvisionedInstance.objects.create(
                name="seed",
                aws_region="us-west-2",
                instance_id="i-123",
                instance_type="t3",
                ami_id="ami-123",
                public_ip="1.2.3.4",
            )
            ReleaseTarget.objects.create(
                blueprint=blueprint,
                name="ems.xyence.io",
                environment="dev",
                target_instance=instance,
                target_instance_ref=str(instance.id),
                fqdn="ems.xyence.io",
                tls_json={"mode": "nginx+acme", "acme_email": "admin@xyence.io"},
                runtime_json={"remote_root": "/var/lib/xyn/ems", "compose_file_path": "docker-compose.yml"},
            )
            release = Release.objects.create(
                blueprint=blueprint,
                release_plan=plan,
                version="v40",
                status="published",
                build_state="ready",
            )
            deployment = Deployment.objects.create(
                idempotency_key="k1",
                idempotency_base="b1",
                release=release,
                instance=instance,
                release_plan=plan,
                status="queued",
            )
            plan_json = {
                "steps": [{"name": "deploy", "commands": ["echo deploy"]}],
                "tasks": [
                    {"id": "tls.acme_http01"},
                    {"id": "ingress.nginx_tls_configure"},
                    {"id": "verify.public_https"},
                ],
            }
            responses = [
                self._ssm_result(),  # deploy step
                self._ssm_result(),  # tls issue
                self._ssm_result(),  # tls configure
                self._ssm_result(status="Failed", code=50, stderr="tls_error_code=https_health_failed\n"),
            ]
            with (
                mock.patch("xyn_orchestrator.deployments._run_ssm_commands", side_effect=responses),
                mock.patch("xyn_orchestrator.deployments._verify_public_https_from_backend", return_value=(True, "")),
                mock.patch("xyn_orchestrator.deployments._load_default_compose", return_value=None),
            ):
                execution = execute_release_plan_deploy(deployment, release, instance, plan, plan_json)
            deployment.refresh_from_db()
            self.assertEqual(deployment.status, "failed")
            self.assertIn("https_health_failed", deployment.error_message)
            self.assertEqual(execution.get("status"), "failed")
            self.assertEqual((execution.get("error") or {}).get("code"), "https_health_failed")

    @override_settings(MEDIA_URL="/media/")
    def test_source_build_fallback_uses_clean_checkout_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir, override_settings(MEDIA_ROOT=tmpdir):
            blueprint = Blueprint.objects.create(name="ems.platform", namespace="core")
            plan = ReleasePlan.objects.create(
                name="Plan",
                target_kind="blueprint",
                target_fqn="core.ems.platform",
                from_version="",
                to_version="v40",
            )
            instance = ProvisionedInstance.objects.create(
                name="seed",
                aws_region="us-west-2",
                instance_id="i-123",
                instance_type="t3",
                ami_id="ami-123",
            )
            release = Release.objects.create(
                blueprint=blueprint,
                release_plan=plan,
                version="v40",
                status="published",
                build_state="ready",
            )
            deployment = Deployment.objects.create(
                idempotency_key="k2",
                idempotency_base="b2",
                release=release,
                instance=instance,
                release_plan=plan,
                status="queued",
            )
            plan_json = {
                "steps": [{"name": "deploy", "commands": ["docker pull private/repo:tag"]}],
                "tasks": [],
            }
            second = self._ssm_result(status="Success", code=0)
            calls = []

            def _fake_run(_instance_id, _region, commands):
                calls.append(commands)
                if len(calls) == 1:
                    raise RuntimeError("no basic auth credentials")
                return second

            with (
                mock.patch("xyn_orchestrator.deployments._run_ssm_commands", side_effect=_fake_run),
                mock.patch("xyn_orchestrator.deployments._load_default_compose", return_value=None),
            ):
                execute_release_plan_deploy(deployment, release, instance, plan, plan_json)
            fallback_commands = "\n".join(calls[-1])
            self.assertIn("deploy-", fallback_commands)
            self.assertIn("rm -rf \"$ROOT/xyn-api\" \"$ROOT/xyn-ui\"", fallback_commands)
            self.assertIn("git clone --depth 1 --branch main https://github.com/Xyence/xyn-api \"$ROOT/xyn-api\"", fallback_commands)
            self.assertIn("git clone --depth 1 --branch main https://github.com/Xyence/xyn-ui \"$ROOT/xyn-ui\"", fallback_commands)
            self.assertIn("EMS_CERTS_PATH=\"$STATE/certs/current\"", fallback_commands)
            self.assertIn("mkdir -p \"$STATE/certs/current\" \"$STATE/acme-webroot\"", fallback_commands)
            self.assertNotIn("git -C \"$ROOT/xyn-api\" pull --ff-only", fallback_commands)
