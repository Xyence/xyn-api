import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from django.test import TestCase
from jsonschema import Draft202012Validator

from xyn_orchestrator.blueprints import _generate_implementation_plan, _select_context_packs_for_dev_task
from xyn_orchestrator.worker_tasks import _apply_scaffold_for_work_item, _collect_git_diff, _mark_noop_codegen
from xyn_orchestrator.models import Blueprint, ContextPack


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
        self.assertGreaterEqual(len(plan.get("work_items", [])), 8)

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

    def test_codegen_no_changes_marks_failure(self):
        errors = []
        success = _mark_noop_codegen(False, "noop-item", errors)
        self.assertFalse(success)
        self.assertEqual(errors[0]["code"], "no_changes")
