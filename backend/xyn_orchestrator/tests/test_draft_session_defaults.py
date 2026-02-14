import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile

from xyn_orchestrator.models import Blueprint, ContextPack, BlueprintDraftSession, DraftSessionRevision, DraftSessionVoiceNote


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
            is_default=False,
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
        self.assertNotIn(str(self.namespace_pack.id), ids)
        self.assertNotIn(str(self.project_pack.id), ids)
        self.assertNotIn(str(self.coder.id), ids)

    def test_context_pack_defaults_include_scope_defaults_when_marked_default(self):
        self.namespace_pack.is_default = True
        self.namespace_pack.save(update_fields=["is_default", "updated_at"])
        self.project_pack.is_default = True
        self.project_pack.save(update_fields=["is_default", "updated_at"])

        response = self.client.get(
            "/xyn/api/context-pack-defaults",
            {
                "draft_kind": "blueprint",
                "namespace": "core",
                "project_key": "core.ems.platform",
            },
        )
        self.assertEqual(response.status_code, 200)
        ids = set(response.json()["recommended_context_pack_ids"])
        self.assertIn(str(self.namespace_pack.id), ids)
        self.assertIn(str(self.project_pack.id), ids)

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
        session = BlueprintDraftSession.objects.get(id=session_id)
        session.current_draft_json = {
            "apiVersion": "xyn.blueprint/v1",
            "kind": "SolutionBlueprint",
            "metadata": {"name": "demo-test", "namespace": "core"},
            "releaseSpec": {
                "apiVersion": "xyn.seed/v1",
                "kind": "Release",
                "metadata": {"name": "demo-test", "namespace": "core"},
                "backend": {"type": "compose"},
                "components": [{"name": "api", "image": "example/demo:latest"}],
            },
        }
        session.save(update_fields=["current_draft_json", "updated_at"])

        submit = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/submit",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(submit.status_code, 200)
        submit_data = submit.json()
        payload = submit_data["submission_payload"]
        self.assertEqual(payload["initial_prompt"], "Create EMS blueprint")
        self.assertEqual(payload["source_artifacts"][0]["type"], "audio_transcript")
        self.assertEqual(submit_data.get("entity_type"), "blueprint")
        entity_id = submit_data.get("entity_id")
        self.assertTrue(entity_id)
        published = Blueprint.objects.get(id=entity_id)
        self.assertTrue((published.spec_text or "").strip())
        self.assertIn('"apiVersion": "xyn.blueprint/v1"', published.spec_text)

    def test_delete_draft_session(self):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Delete me",
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        self.assertTrue(BlueprintDraftSession.objects.filter(id=session_id).exists())

        deleted = self.client.delete(f"/xyn/api/draft-sessions/{session_id}")
        self.assertEqual(deleted.status_code, 200)
        self.assertFalse(BlueprintDraftSession.objects.filter(id=session_id).exists())

    def test_initial_prompt_locked_blocks_patch(self):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Prompt lock test",
                    "initial_prompt": "Original prompt",
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        session = BlueprintDraftSession.objects.get(id=session_id)
        session.current_draft_json = {
            "apiVersion": "xyn.blueprint/v1",
            "kind": "SolutionBlueprint",
            "metadata": {"name": "prompt-lock-test", "namespace": "core"},
            "releaseSpec": {
                "apiVersion": "xyn.seed/v1",
                "kind": "Release",
                "metadata": {"name": "prompt-lock-test", "namespace": "core"},
                "backend": {"type": "compose"},
                "components": [{"name": "api", "image": "example/demo:latest"}],
            },
        }
        session.save(update_fields=["current_draft_json", "updated_at"])
        session.initial_prompt_locked = True
        session.save(update_fields=["initial_prompt_locked", "updated_at"])
        patch = self.client.patch(
            f"/xyn/api/draft-sessions/{session_id}",
            data=json.dumps({"initial_prompt": "Changed later"}),
            content_type="application/json",
        )
        self.assertEqual(patch.status_code, 400)
        self.assertIn("immutable", patch.json().get("error", ""))

    def test_draft_session_revisions_list_paginated_and_searchable(self):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Revision history",
                    "initial_prompt": "Create app",
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        session = BlueprintDraftSession.objects.get(id=session_id)
        for idx in range(7):
            DraftSessionRevision.objects.create(
                draft_session=session,
                revision_number=idx + 1,
                action="revise" if idx else "generate",
                instruction=f"change {idx}",
                draft_json={"kind": "SolutionBlueprint"},
                requirements_summary=f"summary {idx}",
                diff_summary=f"diff {idx}",
                validation_errors_json=[],
            )
        page1 = self.client.get(f"/xyn/api/draft-sessions/{session_id}/revisions", {"page": 1, "page_size": 5})
        self.assertEqual(page1.status_code, 200)
        payload1 = page1.json()
        self.assertEqual(payload1["total"], 7)
        self.assertEqual(len(payload1["revisions"]), 5)
        self.assertEqual(payload1["revisions"][0]["revision_number"], 7)
        page2 = self.client.get(f"/xyn/api/draft-sessions/{session_id}/revisions", {"page": 2, "page_size": 5})
        self.assertEqual(page2.status_code, 200)
        self.assertEqual(len(page2.json()["revisions"]), 2)
        search = self.client.get(f"/xyn/api/draft-sessions/{session_id}/revisions", {"q": "change 3"})
        self.assertEqual(search.status_code, 200)
        self.assertEqual(search.json()["total"], 1)

    def test_draft_sessions_list_filters(self):
        s1 = BlueprintDraftSession.objects.create(
            name="Draft one",
            title="Draft one",
            draft_kind="blueprint",
            status="drafting",
            namespace="core",
            project_key="core.ems.platform",
        )
        BlueprintDraftSession.objects.create(
            name="Draft two",
            title="Draft two",
            draft_kind="solution",
            status="published",
            namespace="lab",
            project_key="lab.other",
        )
        response = self.client.get("/xyn/api/draft-sessions", {"status": "drafting", "project_key": "core.ems.platform"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["sessions"]), 1)
        self.assertEqual(payload["sessions"][0]["id"], str(s1.id))

    def test_upload_voice_note_requires_session_id(self):
        audio = SimpleUploadedFile("sample.wav", b"RIFF....WAVEfmt ", content_type="audio/wav")
        response = self.client.post("/xyn/api/voice-notes", {"file": audio})
        self.assertEqual(response.status_code, 400)
        self.assertIn("session_id", response.json().get("error", ""))

    def test_list_draft_session_voice_notes(self):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Voice list",
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        audio = SimpleUploadedFile("sample.wav", b"RIFF....WAVEfmt ", content_type="audio/wav")
        upload = self.client.post("/xyn/api/voice-notes", {"file": audio, "session_id": session_id})
        self.assertEqual(upload.status_code, 200)
        self.assertEqual(DraftSessionVoiceNote.objects.filter(draft_session_id=session_id).count(), 1)
        listed = self.client.get(f"/xyn/api/draft-sessions/{session_id}/voice-notes")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.json()["voice_notes"]), 1)

    def test_blueprints_list_includes_active_draft_count(self):
        BlueprintDraftSession.objects.create(
            name="Draft count",
            title="Draft count",
            draft_kind="blueprint",
            status="drafting",
            project_key="core.ems",
        )
        response = self.client.get("/xyn/api/blueprints")
        self.assertEqual(response.status_code, 200)
        blueprints = response.json()["blueprints"]
        match = next(item for item in blueprints if item["id"] == str(self.blueprint.id))
        self.assertEqual(match["active_draft_count"], 1)

    def test_submit_uses_session_project_key_for_blueprint_name(self):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Targeted submit",
                    "namespace": "core",
                    "project_key": "core.test-josh",
                    "initial_prompt": "Create EMS blueprint",
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        session = BlueprintDraftSession.objects.get(id=session_id)
        session.current_draft_json = {
            "apiVersion": "xyn.blueprint/v1",
            "kind": "SolutionBlueprint",
            "metadata": {"name": "subscriber-notes-dev-demo", "namespace": "xyence.demo"},
            "releaseSpec": {
                "apiVersion": "xyn.seed/v1",
                "kind": "Release",
                "metadata": {"name": "subscriber-notes-dev-demo", "namespace": "xyence.demo"},
                "backend": {"type": "compose"},
                "components": [{"name": "api", "image": "example/demo:latest"}],
            },
        }
        session.save(update_fields=["current_draft_json", "updated_at"])

        submit = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/submit",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(submit.status_code, 200)
        entity_id = submit.json().get("entity_id")
        self.assertTrue(entity_id)
        published = Blueprint.objects.get(id=entity_id)
        self.assertEqual(published.namespace, "core")
        self.assertEqual(published.name, "test-josh")
