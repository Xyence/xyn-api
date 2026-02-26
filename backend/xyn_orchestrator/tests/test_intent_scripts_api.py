import json
import os
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import IntentScript, LedgerEvent, RoleBinding, UserIdentity, Workspace


class IntentScriptsApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username="intent-admin", password="pass", is_staff=True)
        self.client.force_login(self.user)
        self.identity = UserIdentity.objects.create(provider="oidc", issuer="https://issuer", subject="intent-admin", email="intent-admin@example.com")
        RoleBinding.objects.create(user_identity=self.identity, scope_kind="platform", role="platform_admin")
        self.workspace, _ = Workspace.objects.get_or_create(slug="platform-builder", defaults={"name": "Platform Builder"})
        session = self.client.session
        session["user_identity_id"] = str(self.identity.id)
        session.save()
        os.environ["XYN_INTENT_ENGINE_V1"] = "1"

    def tearDown(self):
        os.environ.pop("XYN_INTENT_ENGINE_V1", None)

    def _create_workflow(self) -> str:
        response = self.client.post(
            "/xyn/api/workflows",
            data=json.dumps(
                {
                    "workspace_id": str(self.workspace.id),
                    "title": "Intent Tour",
                    "slug": "intent-tour",
                    "profile": "tour",
                    "category_slug": "xyn_usage",
                    "visibility_type": "authenticated",
                    "workflow_spec_json": {
                        "profile": "tour",
                        "schema_version": 1,
                        "title": "Intent Tour",
                        "description": "tour for testing",
                        "category_slug": "xyn_usage",
                        "steps": [
                            {
                                "id": "s1",
                                "type": "modal",
                                "title": "Open home",
                                "body_md": "Open workspace home.",
                                "route": "/app/home",
                            }
                        ],
                    },
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        return response.json()["workflow"]["id"]

    def _create_artifact(self) -> str:
        response = self.client.post(
            "/xyn/api/artifacts/create-draft-session",
            data=json.dumps({"title": "Intent Draft", "kind": "blueprint"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        return response.json()["artifact_id"]

    def _create_article_artifact(
        self,
        *,
        title: str,
        category: str = "web",
        summary: str = "",
        body: str = "",
        format: str = "article",
        intent: str = "",
    ) -> str:
        response = self.client.post(
            "/xyn/api/xyn/intent/apply",
            data=json.dumps(
                {
                    "action_type": "CreateDraft",
                    "artifact_type": "ArticleDraft",
                    "payload": {
                        "title": title,
                        "category": category,
                        "format": format,
                        "intent": intent,
                        "summary": summary,
                        "body": body,
                    },
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        return response.json()["artifact_id"]

    def test_generate_intent_script_from_tour(self):
        workflow_id = self._create_workflow()
        response = self.client.post(
            "/xyn/api/intent-scripts/generate",
            data=json.dumps(
                {
                    "scope_type": "tour",
                    "scope_ref_id": workflow_id,
                    "audience": "developer",
                    "length_target": "short",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        payload = response.json()["item"]
        self.assertEqual(payload["scope_type"], "tour")
        self.assertTrue(payload["script_json"]["scenes"])

    def test_generate_and_update_intent_script_from_artifact_emits_ledger_update(self):
        artifact_id = self._create_artifact()
        response = self.client.post(
            "/xyn/api/intent-scripts/generate",
            data=json.dumps(
                {
                    "scope_type": "artifact",
                    "scope_ref_id": artifact_id,
                    "audience": "investor",
                    "length_target": "medium",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        script_id = response.json()["item"]["intent_script_id"]
        script = IntentScript.objects.get(id=script_id)
        self.assertEqual(script.scope_type, "artifact")
        self.assertEqual(str(script.artifact_id), artifact_id)
        self.assertTrue(
            LedgerEvent.objects.filter(
                artifact_id=artifact_id,
                action="artifact.update",
                summary__icontains="Generated intent script",
            ).exists()
        )

        patch = self.client.patch(
            f"/xyn/api/intent-scripts/{script_id}",
            data=json.dumps({"status": "final", "title": "Updated Intent Script"}),
            content_type="application/json",
        )
        self.assertEqual(patch.status_code, 200, patch.content.decode())
        script.refresh_from_db()
        self.assertEqual(script.status, "final")
        self.assertEqual(script.title, "Updated Intent Script")

        listing = self.client.get("/xyn/api/intent-scripts", {"scope_type": "artifact", "scope_ref_id": artifact_id})
        self.assertEqual(listing.status_code, 200, listing.content.decode())
        self.assertTrue(any(item["intent_script_id"] == script_id for item in listing.json().get("items", [])))

    def test_generate_intent_script_from_article_uses_content_only(self):
        body = (
            "What I did on my summer vacation included documenting lessons from field deployments. "
            "I focused on governance ledger workflows and how teams review changes clearly. "
            "The article explains practical steps and outcomes for telecom engineering teams."
        )
        artifact_id = self._create_article_artifact(
            title="What I Did On My Summer Vacation",
            summary="A practical account of governance ledger lessons.",
            body=body,
        )

        response = self.client.post(
            "/xyn/api/intent-scripts/generate",
            data=json.dumps(
                {
                    "scope_type": "artifact",
                    "scope_ref_id": artifact_id,
                    "audience": "developer",
                    "length_target": "short",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        item = response.json()["item"]
        serialized = json.dumps(item.get("script_json") or {}).lower()
        script_text = str(item.get("script_text") or "").lower()
        self.assertNotIn("/app/artifacts", serialized)
        self.assertNotIn("ui_route", serialized)
        self.assertNotIn("/app/artifacts", script_text)
        self.assertNotIn("route:", script_text)
        self.assertNotIn("provisional", script_text)
        self.assertNotIn("content hash", script_text)
        self.assertNotIn("schema", script_text)
        self.assertNotIn("validation", script_text)
        self.assertNotIn("owner", script_text)
        self.assertIn("summer vacation", script_text)

    def test_article_intent_script_model_prompt_uses_content_only_payload(self):
        body = (
            "This article explains governance ledger design choices. "
            "It focuses on deterministic transitions and clear accountability."
        )
        artifact_id = self._create_article_artifact(
            title="Governance Ledger Notes",
            summary="Design notes for accountability.",
            body=body,
        )
        captured = {}

        def _fake_invoke(*, resolved_config, messages):
            captured["messages"] = messages
            return {
                "content": json.dumps(
                    {
                        "title": "Governance Ledger Notes",
                        "scenes": [
                            {"id": "s1", "title": "Hook / Premise", "voiceover": "Intro", "on_screen": "What this is about"},
                            {"id": "s2", "title": "Setup / Context", "voiceover": "Context", "on_screen": "The setup"},
                            {"id": "s3", "title": "Close / Next Step", "voiceover": "Close", "on_screen": "Closing thought"},
                        ],
                        "duration_hint": "60-90s",
                    }
                ),
                "model": "fake-model",
            }

        with patch("xyn_orchestrator.xyn_api.resolve_ai_config", return_value={"model_name": "fake-model"}):
            with patch("xyn_orchestrator.xyn_api.invoke_model", side_effect=_fake_invoke):
                response = self.client.post(
                    "/xyn/api/intent-scripts/generate",
                    data=json.dumps(
                        {
                            "scope_type": "artifact",
                            "scope_ref_id": artifact_id,
                            "audience": "developer",
                            "length_target": "short",
                        }
                    ),
                    content_type="application/json",
                )

        self.assertEqual(response.status_code, 200, response.content.decode())
        user_message = next(
            (msg for msg in (captured.get("messages") or []) if isinstance(msg, dict) and msg.get("role") == "user"),
            {},
        )
        payload = json.loads(str(user_message.get("content") or "{}"))
        content_only = {key: value for key, value in payload.items() if key not in {"constraints", "output_schema"}}
        serialized = json.dumps(content_only).lower()
        self.assertNotIn("artifact_id", serialized)
        self.assertNotIn("/app/artifacts", serialized)
        self.assertNotIn("schema_version", serialized)
        self.assertNotIn("content_hash", serialized)
        self.assertNotIn("owner", serialized)
        self.assertNotIn("lineage", serialized)

    def test_generate_intent_script_from_article_requires_summary_or_body(self):
        artifact_id = self._create_article_artifact(title="Empty Article", summary="", body="")
        response = self.client.post(
            "/xyn/api/intent-scripts/generate",
            data=json.dumps(
                {
                    "scope_type": "artifact",
                    "scope_ref_id": artifact_id,
                    "audience": "developer",
                    "length_target": "short",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400, response.content.decode())
        payload = response.json()
        self.assertEqual(payload.get("status"), "MissingFields")
        self.assertIn("Add a summary or body", str(payload.get("message") or ""))

    def test_generate_intent_script_for_explainer_article_uses_existing_scenes(self):
        artifact_id = self._create_article_artifact(
            title="Summer Vacation Explainer",
            category="web",
            format="explainer_video",
            intent="Explain summer vacation outcomes for telecom engineers.",
        )
        response = self.client.post(
            "/xyn/api/intent-scripts/generate",
            data=json.dumps(
                {
                    "scope_type": "artifact",
                    "scope_ref_id": artifact_id,
                    "audience": "developer",
                    "length_target": "short",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content.decode())
        scenes = (((response.json() or {}).get("item") or {}).get("script_json") or {}).get("scenes") or []
        self.assertTrue(len(scenes) >= 3)
