import json
import os
import sys
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from unittest import mock

from django.test import TestCase
from jsonschema import Draft202012Validator
import yaml

from xyn_orchestrator.blueprints import (
    _build_module_catalog,
    _build_run_history_summary,
    _generate_implementation_plan,
    _release_target_payload,
    _select_context_packs_for_dev_task,
    _write_run_artifact,
)
from xyn_orchestrator.xyn_api import _validate_release_target_payload
from xyn_orchestrator.worker_tasks import (
    _apply_scaffold_for_work_item,
    _collect_git_diff,
    _build_deploy_manifest,
    _merge_release_env,
    _mark_noop_codegen,
    _redact_secrets,
    _stage_all,
    _route53_ensure_with_noop,
    _run_remote_deploy,
    _work_item_capabilities,
)
from xyn_orchestrator.models import Blueprint, ContextPack, DevTask, Run, ReleaseTarget


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
            "errors": [],
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
            "runtime": {"type": "docker-compose", "transport": "ssm", "remote_root": "/opt/xyn/apps/ems"},
            "tls": {"mode": "nginx+acme", "acme_email": "admin@xyence.io", "redirect_http_to_https": True},
            "env": {"EMS_JWT_SECRET": "dev-secret"},
            "secret_refs": [],
            "created_at": "2026-02-07T00:00:00Z",
            "updated_at": "2026-02-07T00:00:00Z",
        }
        schema = self._load_schema("release_target.v1.schema.json")
        errors = list(Draft202012Validator(schema).iter_errors(payload))
        self.assertEqual(errors, [], f"Schema errors: {errors}")

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
        rationale = plan.get("plan_rationale", {})
        self.assertIn("dns-route53", rationale.get("modules_selected", []))

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
