import copy
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator import services
from xyn_orchestrator import worker_tasks
from xyn_orchestrator.models import BlueprintDraftSession


def _baseline_draft() -> dict:
    return {
        "apiVersion": "xyn.blueprint/v1",
        "kind": "SolutionBlueprint",
        "metadata": {"name": "demo", "namespace": "core", "labels": {"team": "xyn"}},
        "description": "base",
        "releaseSpec": {
            "apiVersion": "xyn.seed/v1",
            "kind": "Release",
            "metadata": {"name": "demo", "namespace": "core", "labels": {"service": "api"}},
            "backend": {"type": "compose", "config": {"x_keep": "yes"}},
            "components": [
                {
                    "name": "api",
                    "image": "example/api:1",
                    "env": {"KEEP_ENV": "1"},
                    "ports": [{"containerPort": 8080}],
                },
                {
                    "name": "web",
                    "image": "example/web:1",
                    "ports": [{"containerPort": 3000}],
                },
            ],
        },
    }


class DraftRevisionStabilityTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="staff2", password="pass", is_staff=True)
        self.session = BlueprintDraftSession.objects.create(
            name="rev-stable",
            title="rev-stable",
            draft_kind="blueprint",
            blueprint_kind="solution",
            initial_prompt="Create demo app",
            source_artifacts=[{"type": "audio_transcript", "content": "voice context"}],
            current_draft_json=_baseline_draft(),
            requirements_summary="truncated summary",
            created_by=user,
            updated_by=user,
        )

    @patch("xyn_orchestrator.services._openai_revise_blueprint")
    def test_revise_uses_baseline_and_not_truncated_summary(self, mock_revise):
        revised = copy.deepcopy(_baseline_draft())
        revised["description"] = "updated via instruction"
        revised["releaseSpec"]["components"] = revised["releaseSpec"]["components"][:1]
        revised["releaseSpec"]["backend"] = {"type": "compose"}  # drops config; merge should preserve
        mock_revise.return_value = (revised, None)

        services.revise_blueprint_draft(str(self.session.id), "Update description only")
        self.session.refresh_from_db()

        self.assertEqual(self.session.status, "ready")
        self.assertEqual(self.session.validation_errors_json, [])
        self.assertEqual(self.session.current_draft_json.get("description"), "updated via instruction")
        backend = self.session.current_draft_json["releaseSpec"]["backend"]
        self.assertEqual(backend.get("config", {}).get("x_keep"), "yes")
        self.assertEqual(len(self.session.current_draft_json["releaseSpec"]["components"]), 2)
        self.assertEqual(mock_revise.call_count, 1)
        called_kwargs = mock_revise.call_args.kwargs
        self.assertEqual(called_kwargs.get("baseline_draft_json", {}).get("metadata", {}).get("name"), "demo")
        self.assertEqual(called_kwargs.get("initial_prompt"), "Create demo app")
        self.assertEqual(called_kwargs.get("prompt_sources"), ["voice context"])

    @patch("xyn_orchestrator.services._openai_generate_blueprint")
    def test_initial_prompt_locks_after_first_generation(self, mock_generate):
        mock_generate.return_value = (_baseline_draft(), None)
        services.generate_blueprint_draft(str(self.session.id))
        self.session.refresh_from_db()
        self.assertTrue(self.session.initial_prompt_locked)

    def test_normalize_generated_blueprint_converts_env_list_to_object_and_secret_refs(self):
        draft = _baseline_draft()
        draft["releaseSpec"]["components"][0]["env"] = [
            {"name": "APP_ENV", "value": "dev"},
            {"name": "DB_USER", "valueFrom": {"secretRef": {"name": "db-secret", "key": "username"}}},
        ]

        normalized = services._normalize_generated_blueprint(draft)
        env_payload = normalized["releaseSpec"]["components"][0]["env"]
        self.assertEqual(env_payload, {"APP_ENV": "dev"})
        self.assertEqual(
            normalized["releaseSpec"]["components"][0]["secretRefs"],
            [{"name": "db-secret", "key": "username", "targetEnv": "DB_USER"}],
        )

    def test_worker_normalize_generated_blueprint_converts_env_list_to_object_and_secret_refs(self):
        draft = _baseline_draft()
        draft["releaseSpec"]["components"][0]["env"] = [
            {"name": "APP_ENV", "value": "dev"},
            {"name": "DB_PASS", "valueFrom": {"secretRef": {"name": "db-secret", "key": "password"}}},
        ]

        normalized = worker_tasks._normalize_generated_blueprint(draft)
        env_payload = normalized["releaseSpec"]["components"][0]["env"]
        self.assertEqual(env_payload, {"APP_ENV": "dev"})
        self.assertEqual(
            normalized["releaseSpec"]["components"][0]["secretRefs"],
            [{"name": "db-secret", "key": "password", "targetEnv": "DB_PASS"}],
        )
