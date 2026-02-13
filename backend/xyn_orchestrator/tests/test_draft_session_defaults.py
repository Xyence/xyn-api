import json

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import Blueprint, ContextPack, BlueprintDraftSession


class DraftSessionDefaultsTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="staff", password="pass", is_staff=True)
        self.client.force_login(user)
        self.blueprint = Blueprint.objects.create(name="ems", namespace="core", description="")

        self.platform = ContextPack.objects.create(
            name="xyn-platform-canon",
            purpose="planner",
            scope="global",
            version="1",
            content_markdown="platform",
            is_active=True,
        )
        self.planner = ContextPack.objects.create(
            name="xyn-planner-canon",
            purpose="planner",
            scope="global",
            version="1",
            content_markdown="planner",
            is_active=True,
        )
        self.coder = ContextPack.objects.create(
            name="xyn-coder-canon",
            purpose="coder",
            scope="global",
            version="1",
            content_markdown="coder",
            is_active=True,
        )
        self.namespace_pack = ContextPack.objects.create(
            name="xyence-engineering-conventions",
            purpose="planner",
            scope="namespace",
            namespace="core",
            version="1",
            content_markdown="ns",
            is_active=True,
        )
        self.project_pack = ContextPack.objects.create(
            name="ems-platform-blueprint",
            purpose="planner",
            scope="project",
            project_key="core.ems.platform",
            version="1",
            content_markdown="proj",
            is_active=True,
        )

    def test_context_pack_defaults_blueprint_scope_rules(self):
        response = self.client.get(
            "/xyn/api/context-pack-defaults",
            {
                "draft_kind": "blueprint",
                "namespace": "core",
                "project_key": "core.ems.platform",
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        ids = set(payload["recommended_context_pack_ids"])
        self.assertIn(str(self.platform.id), ids)
        self.assertIn(str(self.planner.id), ids)
        self.assertIn(str(self.namespace_pack.id), ids)
        self.assertIn(str(self.project_pack.id), ids)
        self.assertNotIn(str(self.coder.id), ids)

    def test_context_pack_defaults_solution_includes_coder(self):
        response = self.client.get(
            "/xyn/api/context-pack-defaults",
            {"draft_kind": "solution", "namespace": "core", "project_key": "core.ems.platform"},
        )
        self.assertEqual(response.status_code, 200)
        ids = set(response.json()["recommended_context_pack_ids"])
        self.assertIn(str(self.coder.id), ids)

    def test_new_draft_session_uses_untitled_title_and_default_packs(self):
        response = self.client.post(
            f"/xyn/api/blueprints/{self.blueprint.id}/draft-sessions",
            data=json.dumps({"kind": "blueprint", "name": ""}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        session_id = response.json()["session_id"]
        session = BlueprintDraftSession.objects.get(id=session_id)
        self.assertEqual(session.title, "Untitled draft")
        self.assertEqual(session.name, "Untitled draft")
        self.assertEqual(session.draft_kind, "blueprint")
        self.assertIn(str(self.platform.id), session.selected_context_pack_ids)
        self.assertIn(str(self.planner.id), session.selected_context_pack_ids)
        self.assertNotIn(str(self.coder.id), session.selected_context_pack_ids)

    def test_submit_includes_prompt_and_source_artifacts(self):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Untitled draft",
                    "initial_prompt": "Create EMS blueprint",
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                    "source_artifacts": [{"type": "audio_transcript", "content": "voice transcript"}],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]

        submit = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/submit",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(submit.status_code, 200)
        payload = submit.json()["submission_payload"]
        self.assertEqual(payload["initial_prompt"], "Create EMS blueprint")
        self.assertEqual(payload["source_artifacts"][0]["type"], "audio_transcript")
