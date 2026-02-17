import json
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile

from xyn_orchestrator.models import (
    Blueprint,
    BlueprintDraftSession,
    ContextPack,
    DraftSessionRevision,
    DraftSessionVoiceNote,
    Environment,
    ProvisionedInstance,
    ReleaseTarget,
)
from xyn_orchestrator.blueprints import (
    ensure_default_release_target,
    _generate_implementation_plan,
    _release_target_payload,
    _sanitize_release_spec_for_xynseed,
)
from xyn_orchestrator.services import _normalize_generated_blueprint


class DraftSessionDefaultsTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="staff", password="pass", is_staff=True)
        self.user = user
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
            name="project-blueprint-pack",
            purpose="planner",
            scope="project",
            project_key="core.demo.app",
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
                "project_key": "core.demo.app",
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
                "project_key": "core.demo.app",
            },
        )
        self.assertEqual(response.status_code, 200)
        ids = set(response.json()["recommended_context_pack_ids"])
        self.assertIn(str(self.namespace_pack.id), ids)
        self.assertIn(str(self.project_pack.id), ids)

    def test_context_pack_defaults_solution_includes_coder(self):
        response = self.client.get(
            "/xyn/api/context-pack-defaults",
            {"draft_kind": "solution", "namespace": "core", "project_key": "core.demo.app"},
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
            project_key="core.demo.app",
        )
        BlueprintDraftSession.objects.create(
            name="Draft two",
            title="Draft two",
            draft_kind="solution",
            status="published",
            namespace="lab",
            project_key="lab.other",
        )
        response = self.client.get("/xyn/api/draft-sessions", {"status": "drafting", "project_key": "core.demo.app"})
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

    def test_publish_no_longer_creates_blueprint(self):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Publish alias snapshot",
                    "namespace": "core",
                    "project_key": "core.publish-alias",
                    "initial_prompt": "Create EMS blueprint",
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        session = BlueprintDraftSession.objects.get(id=session_id)
        session.current_draft_json = self._build_valid_solution_draft(name="publish-alias")
        session.save(update_fields=["current_draft_json", "updated_at"])
        before = Blueprint.objects.count()

        response = self.client.post(f"/xyn/api/draft-sessions/{session_id}/publish", content_type="application/json")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload.get("ok"))
        self.assertTrue(payload.get("deprecated"))
        self.assertTrue(payload.get("snapshot_id"))
        self.assertEqual(Blueprint.objects.count(), before)
        latest_revision = DraftSessionRevision.objects.filter(draft_session_id=session_id).order_by("-revision_number").first()
        self.assertIsNotNone(latest_revision)
        self.assertEqual(latest_revision.action, "snapshot")

    def test_snapshot_creates_history_entry_and_no_blueprint(self):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Snapshot test",
                    "namespace": "core",
                    "project_key": "core.snapshot-test",
                    "initial_prompt": "Create EMS blueprint",
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        session = BlueprintDraftSession.objects.get(id=session_id)
        session.current_draft_json = self._build_valid_solution_draft(name="snapshot-test")
        session.save(update_fields=["current_draft_json", "updated_at"])
        before = Blueprint.objects.count()

        response = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/snapshot",
            data=json.dumps({"note": "manual snapshot"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload.get("ok"))
        self.assertTrue(payload.get("snapshot_id"))
        self.assertEqual(Blueprint.objects.count(), before)
        revision = DraftSessionRevision.objects.get(id=payload["snapshot_id"])
        self.assertEqual(revision.action, "snapshot")
        self.assertIn("manual snapshot", revision.instruction)

    def test_submit_is_only_endpoint_that_writes_blueprint(self):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Submit only writes",
                    "namespace": "core",
                    "project_key": "core.submit-only",
                    "initial_prompt": "Create EMS blueprint",
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        session = BlueprintDraftSession.objects.get(id=session_id)
        session.current_draft_json = self._build_valid_solution_draft(name="submit-only")
        session.save(update_fields=["current_draft_json", "updated_at"])
        before = Blueprint.objects.count()

        publish_response = self.client.post(f"/xyn/api/draft-sessions/{session_id}/publish")
        self.assertEqual(publish_response.status_code, 200)
        snapshot_response = self.client.post(f"/xyn/api/draft-sessions/{session_id}/snapshot")
        self.assertEqual(snapshot_response.status_code, 200)
        self.assertEqual(Blueprint.objects.count(), before)

        submit_response = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/submit",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(submit_response.status_code, 200)
        self.assertEqual(Blueprint.objects.count(), before + 1)

    @mock.patch("xyn_orchestrator.blueprints._enqueue_job", return_value="job-123")
    @mock.patch("xyn_orchestrator.blueprints._async_mode", return_value="redis")
    def test_generate_auto_resolves_context_when_missing(self, _mock_mode, _mock_enqueue):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Context auto resolve",
                    "namespace": "core",
                    "project_key": "core.context-auto",
                    "initial_prompt": "Create EMS blueprint",
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        BlueprintDraftSession.objects.filter(id=session_id).update(
            context_pack_refs_json=[],
            effective_context_hash="",
            effective_context_preview="",
            context_resolved_at=None,
        )
        response = self.client.post(f"/xyn/api/draft-sessions/{session_id}/enqueue-draft-generation")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload.get("context_stale"))
        self.assertTrue(payload.get("effective_context_hash"))
        self.assertTrue(payload.get("context_resolved_at"))
        session = BlueprintDraftSession.objects.get(id=session_id)
        self.assertTrue(session.effective_context_hash)
        self.assertIsNotNone(session.context_resolved_at)

    def test_extract_release_target_intent_from_prompt_bullets(self):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Intent parse",
                    "namespace": "core",
                    "project_key": "core.intent-parse",
                    "initial_prompt": (
                        "* Target environment: Dev\n"
                        "* Deploy to instance: xyn-seed-dev-1\n"
                        "* Public hostname: josh-test-b.xyence.io\n"
                    ),
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        env = Environment.objects.create(name="Dev", slug="dev")
        instance = ProvisionedInstance.objects.create(
            name="xyn-seed-dev-1",
            environment=env,
            aws_region="us-east-1",
            instance_type="t3.small",
            ami_id="ami-test",
            runtime_substrate="ec2",
            status="running",
            health_status="healthy",
        )
        response = self.client.post(f"/xyn/api/draft-sessions/{session_id}/extract_release_target", data=json.dumps({}), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        intent = payload.get("intent") or {}
        self.assertEqual(intent.get("fqdn"), "josh-test-b.xyence.io")
        self.assertEqual((payload.get("resolved") or {}).get("environment_id"), str(env.id))
        self.assertEqual((payload.get("resolved") or {}).get("instance_id"), str(instance.id))

    def test_extract_returns_400_when_ambiguous_environment(self):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Intent ambiguous env",
                    "namespace": "core",
                    "project_key": "core.intent-ambiguous",
                    "initial_prompt": (
                        "* Target environment: Dev\n"
                        "* Deploy to instance: xyn-seed-dev-1\n"
                        "* Public hostname: ambiguous.xyence.io\n"
                    ),
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        Environment.objects.create(name="Dev", slug="dev-a")
        Environment.objects.create(name="Dev", slug="dev-b")
        response = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/submit",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertEqual(payload.get("code"), "release_target_intent_incomplete")
        self.assertIn("environment", payload.get("fields_missing", []))

    def test_submit_uses_extracted_intent_when_submit_payload_missing(self):
        env = Environment.objects.create(name="Dev", slug="dev")
        instance = ProvisionedInstance.objects.create(
            name="xyn-seed-dev-1",
            environment=env,
            aws_region="us-east-1",
            instance_type="t3.small",
            ami_id="ami-test",
            runtime_substrate="ec2",
            status="running",
            health_status="healthy",
        )
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Intent submit fallback",
                    "namespace": "core",
                    "project_key": "core.intent-submit",
                    "initial_prompt": (
                        "* Target environment: Dev\n"
                        "* Deploy to instance: xyn-seed-dev-1\n"
                        "* Public hostname: fallback.xyence.io\n"
                    ),
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        session = BlueprintDraftSession.objects.get(id=session_id)
        session.current_draft_json = self._build_valid_solution_draft(name="intent-submit")
        session.save(update_fields=["current_draft_json", "updated_at"])
        self.client.post(f"/xyn/api/draft-sessions/{session_id}/extract_release_target", data=json.dumps({}), content_type="application/json")

        response = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/submit",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        blueprint_id = response.json().get("entity_id")
        self.assertTrue(blueprint_id)
        target = ReleaseTarget.objects.get(blueprint_id=blueprint_id, environment="Dev")
        self.assertEqual(target.target_instance_id, instance.id)
        self.assertEqual(target.fqdn, "fallback.xyence.io")

    def test_submit_does_not_create_target_without_confirmation_fields(self):
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Intent incomplete",
                    "namespace": "core",
                    "project_key": "core.intent-incomplete",
                    "initial_prompt": "* Public hostname: incomplete.xyence.io",
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        session = BlueprintDraftSession.objects.get(id=session_id)
        session.current_draft_json = self._build_valid_solution_draft(name="intent-incomplete")
        session.save(update_fields=["current_draft_json", "updated_at"])
        self.client.post(f"/xyn/api/draft-sessions/{session_id}/extract_release_target", data=json.dumps({}), content_type="application/json")

        response = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/submit",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json().get("code"), "release_target_intent_incomplete")

    def _build_valid_solution_draft(self, name: str = "subscriber-notes-dev-demo", namespace: str = "core") -> dict:
        return {
            "apiVersion": "xyn.blueprint/v1",
            "kind": "SolutionBlueprint",
            "metadata": {"name": name, "namespace": namespace},
            "releaseSpec": {
                "apiVersion": "xyn.seed/v1",
                "kind": "Release",
                "metadata": {"name": name, "namespace": namespace},
                "backend": {"type": "compose"},
                "components": [{"name": "api", "image": "example/demo:latest"}],
            },
        }

    def _create_dev_instance(self, name: str = "xyn-seed-dev-1") -> ProvisionedInstance:
        env = Environment.objects.create(name="Dev", slug="dev")
        return ProvisionedInstance.objects.create(
            name=name,
            environment=env,
            aws_region="us-east-1",
            instance_type="t3.small",
            ami_id="ami-test",
            runtime_substrate="ec2",
            status="running",
            health_status="healthy",
        )

    def _create_draft_for_submit(self, title: str = "Auto target draft") -> str:
        response = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": title,
                    "namespace": "core",
                    "project_key": "core.subscriber-notes",
                    "initial_prompt": "Create EMS blueprint",
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        return response.json()["session_id"]

    def test_finalize_submit_auto_creates_default_release_target(self):
        instance = self._create_dev_instance()
        session_id = self._create_draft_for_submit("Auto target")
        session = BlueprintDraftSession.objects.get(id=session_id)
        session.current_draft_json = self._build_valid_solution_draft(name="subscriber-notes")
        session.save(update_fields=["current_draft_json", "updated_at"])

        submit = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/submit",
            data=json.dumps(
                {
                    "release_target": {
                        "environment": "Dev",
                        "target_instance_id": str(instance.id),
                        "fqdn": "diwakar.xyence.io",
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(submit.status_code, 200)
        blueprint_id = submit.json()["entity_id"]
        target = ReleaseTarget.objects.get(blueprint_id=blueprint_id, environment="Dev")
        self.assertTrue(target.auto_generated)
        self.assertEqual(target.target_instance_id, instance.id)
        self.assertEqual(target.fqdn, "diwakar.xyence.io")
        self.assertEqual(target.name, "subscriber-notes-dev-default")
        self.assertEqual((target.tls_json or {}).get("mode"), "host-ingress")
        self.assertEqual((target.tls_json or {}).get("provider"), "traefik")
        self.assertTrue(target.created_by_id)

    def test_finalize_submit_idempotent_reuses_single_default_release_target(self):
        instance = self._create_dev_instance()
        session_id = self._create_draft_for_submit("Idempotent target")
        session = BlueprintDraftSession.objects.get(id=session_id)
        session.current_draft_json = self._build_valid_solution_draft(name="idempotent-demo")
        session.save(update_fields=["current_draft_json", "updated_at"])

        payload = {
            "release_target": {
                "environment": "Dev",
                "target_instance_id": str(instance.id),
                "fqdn": "idempotent.xyence.io",
            }
        }
        first = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/submit",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(first.status_code, 200)
        second = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/submit",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(second.status_code, 200)
        blueprint_id = first.json()["entity_id"]
        self.assertEqual(
            ReleaseTarget.objects.filter(blueprint_id=blueprint_id, environment="Dev", auto_generated=True).count(),
            1,
        )
        target = ReleaseTarget.objects.get(blueprint_id=blueprint_id, environment="Dev", auto_generated=True)
        self.assertEqual((target.tls_json or {}).get("mode"), "host-ingress")

    def test_finalize_submit_manual_release_target_blocks_auto_generation(self):
        instance = self._create_dev_instance()
        blueprint = Blueprint.objects.create(name="manual-existing", namespace="core")
        ReleaseTarget.objects.create(
            blueprint=blueprint,
            name="manual-existing-dev",
            environment="Dev",
            target_instance_ref=str(instance.id),
            target_instance=instance,
            fqdn="manual.xyence.io",
            dns_json={},
            runtime_json={},
            tls_json={},
            env_json={},
            secret_refs_json=[],
            config_json={"editable": True},
            auto_generated=False,
        )
        session_id = self._create_draft_for_submit("Manual target")
        session = BlueprintDraftSession.objects.get(id=session_id)
        session.project_key = "core.manual-existing"
        session.current_draft_json = self._build_valid_solution_draft(name="manual-existing")
        session.save(update_fields=["project_key", "current_draft_json", "updated_at"])

        submit = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/submit",
            data=json.dumps(
                {
                    "release_target": {
                        "environment": "Dev",
                        "target_instance_id": str(instance.id),
                        "fqdn": "manual.xyence.io",
                    }
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(submit.status_code, 200)
        self.assertEqual(ReleaseTarget.objects.filter(blueprint=blueprint, environment="Dev").count(), 1)
        self.assertEqual(ReleaseTarget.objects.filter(blueprint=blueprint, auto_generated=True).count(), 0)

    def test_finalize_submit_updates_existing_auto_target(self):
        instance = self._create_dev_instance()
        blueprint = Blueprint.objects.create(name="auto-update", namespace="core")
        target = ReleaseTarget.objects.create(
            blueprint=blueprint,
            name="stale-target",
            environment="Dev",
            target_instance_ref=str(instance.id),
            target_instance=instance,
            fqdn="old.xyence.io",
            dns_json={"provider": "route53", "ttl": 60},
            runtime_json={"type": "docker-compose", "transport": "ssm", "mode": "compose_images"},
            tls_json={"mode": "none"},
            env_json={},
            secret_refs_json=[],
            config_json={"editable": True},
            auto_generated=True,
        )
        updated, created = ensure_default_release_target(blueprint, "Dev", instance, "new.xyence.io", self.user)
        self.assertFalse(created)
        self.assertEqual(updated.id, target.id)
        self.assertEqual(updated.fqdn, "new.xyence.io")
        self.assertEqual((updated.tls_json or {}).get("mode"), "host-ingress")

    def test_implementation_plan_carries_release_target_environment_id(self):
        instance = self._create_dev_instance()
        blueprint = Blueprint.objects.create(
            name="env-carry",
            namespace="core",
            spec_text=json.dumps(
                {
                    "releaseSpec": {
                        "metadata": {"name": "env-carry", "namespace": "core"},
                        "repoTargets": [
                            {
                                "name": "xyn-api",
                                "url": "https://github.com/Xyence/xyn-api",
                                "ref": "main",
                                "path_root": ".",
                                "auth": "github_app",
                                "allow_write": True,
                            }
                        ],
                        "components": [
                            {
                                "name": "api",
                                "build": {
                                    "repoTarget": "xyn-api",
                                    "context": ".",
                                    "dockerfile": "Dockerfile",
                                },
                            }
                        ],
                    }
                }
            ),
        )
        target = ReleaseTarget.objects.create(
            blueprint=blueprint,
            name="env-carry-dev-default",
            environment="Dev",
            target_instance_ref=str(instance.id),
            target_instance=instance,
            fqdn="env-carry.xyence.io",
            dns_json={"provider": "route53", "ttl": 60},
            runtime_json={"type": "docker-compose", "transport": "ssm", "mode": "compose_images"},
            tls_json={"mode": "host-ingress"},
            env_json={},
            secret_refs_json=[],
            config_json={"editable": True},
            auto_generated=True,
        )

        release_target_payload = _release_target_payload(target)
        self.assertEqual(release_target_payload.get("environment_id"), str(instance.environment_id))

        plan = _generate_implementation_plan(
            blueprint,
            module_catalog={"modules": []},
            run_history_summary={},
            release_target=release_target_payload,
        )
        self.assertEqual(plan.get("release_target_environment_id"), str(instance.environment_id))

    def test_sanitize_release_spec_escapes_secret_ref_interpolation(self):
        release_spec = {
            "components": [
                {
                    "name": "api",
                    "env": {
                        "DB_PASSWORD": "${secretRef:dev/subscriber-notes/db.password}",
                        "UNCHANGED": "${POSTGRES_PASSWORD:-ems}",
                    },
                }
            ]
        }
        sanitized = _sanitize_release_spec_for_xynseed(release_spec)
        env = sanitized["components"][0]["env"]
        self.assertEqual(env["DB_PASSWORD"], "$${secretRef:dev/subscriber-notes/db.password}")
        self.assertEqual(env["UNCHANGED"], "${POSTGRES_PASSWORD:-ems}")

    def test_sanitize_release_spec_normalizes_namespace_for_compose_project(self):
        release_spec = {
            "metadata": {
                "name": "subscriber-notes-dev-demo",
                "namespace": "xyence.demo",
            }
        }
        sanitized = _sanitize_release_spec_for_xynseed(release_spec)
        self.assertEqual(sanitized["metadata"]["namespace"], "xyence-demo")

    def test_non_ems_blueprint_with_image_deploy_includes_remote_deploy_tasks(self):
        blueprint = Blueprint.objects.create(
            name="test-b",
            namespace="core",
            metadata_json={},
            spec_text=json.dumps(
                {
                    "releaseSpec": {
                        "metadata": {"name": "test-b", "namespace": "core"},
                        "repoTargets": [
                            {
                                "name": "xyn-api",
                                "url": "https://github.com/Xyence/xyn-api",
                                "ref": "main",
                                "path_root": ".",
                                "auth": "github_app",
                                "allow_write": True,
                            }
                        ],
                        "components": [
                            {
                                "name": "api",
                                "build": {
                                    "repoTarget": "xyn-api",
                                    "context": ".",
                                    "dockerfile": "Dockerfile",
                                },
                            }
                        ],
                    }
                }
            ),
        )
        release_target = {
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "name": "test-b-dev-default",
            "environment": "Dev",
            "environment_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "target_instance_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "fqdn": "test-b.xyence.io",
            "dns": {"provider": "route53", "ttl": 60},
            "runtime": {"type": "docker-compose", "transport": "ssm", "mode": "compose_images"},
            "tls": {"mode": "host-ingress"},
        }

        plan = _generate_implementation_plan(
            blueprint,
            module_catalog={"modules": []},
            run_history_summary={"acceptance_checks_status": []},
            release_target=release_target,
        )
        ids = {item.get("id") for item in plan.get("work_items", [])}
        self.assertIn("dns.ensure_record.route53", ids)
        self.assertIn("build.publish_images.components", ids)
        self.assertIn("deploy.apply_remote_compose.pull", ids)

    def test_normalize_generated_blueprint_prefers_build_over_image_when_both_present(self):
        draft = {
            "kind": "SolutionBlueprint",
            "releaseSpec": {
                "components": [
                    {
                        "name": "db-migrate",
                        "image": "flyway/flyway:10-alpine",
                        "build": {"context": "./apps/subscriber-notes/db", "dockerfile": "Dockerfile"},
                    }
                ]
            },
        }
        normalized = _normalize_generated_blueprint(draft)
        component = normalized["releaseSpec"]["components"][0]
        self.assertIn("build", component)
        self.assertNotIn("image", component)

    def test_submit_persists_intent_provenance_with_structured_requirements(self):
        prompt = (
            "Create a small telecom-oriented demo application called Subscriber Notes.\n"
            "API requirements: create/list/delete endpoints and a health endpoint.\n"
            "UI requirements: header 'Subscriber Notes - Dev Demo', notes table, add form, delete action.\n"
            "Data model: id, subscriber_id, note_text, created_at.\n"
            "Operational requirements: secrets/config, logging, migrations, idempotent deploy.\n"
            "Definition of done: app is reachable at https://josh.xyence.io.\n"
        )
        create = self.client.post(
            "/xyn/api/draft-sessions",
            data=json.dumps(
                {
                    "kind": "blueprint",
                    "title": "Subscriber Notes",
                    "namespace": "core",
                    "project_key": "core.subscriber-notes",
                    "initial_prompt": prompt,
                    "selected_context_pack_ids": [str(self.platform.id), str(self.planner.id)],
                    "source_artifacts": [{"type": "audio_transcript", "content": "Transcript with deployment notes."}],
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(create.status_code, 200)
        session_id = create.json()["session_id"]
        session = BlueprintDraftSession.objects.get(id=session_id)
        session.current_draft_json = self._build_valid_solution_draft(name="subscriber-notes")
        session.requirements_summary = "Subscriber Notes app with API, UI, data model and operations requirements."
        session.save(update_fields=["current_draft_json", "requirements_summary", "updated_at"])

        submit = self.client.post(
            f"/xyn/api/draft-sessions/{session_id}/submit",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(submit.status_code, 200)
        blueprint = Blueprint.objects.get(id=submit.json()["entity_id"])
        spec = json.loads(blueprint.spec_text or "{}")
        intent = spec.get("intent") or {}
        self.assertEqual(intent.get("sourceDraftSessionId"), session_id)
        self.assertEqual((intent.get("createdFrom") or {}).get("type"), "draft")
        self.assertEqual((intent.get("prompt") or {}).get("text"), session.initial_prompt)
        requirements = intent.get("requirements") or {}
        functional = " ".join(requirements.get("functional") or []).lower()
        ui = " ".join(requirements.get("ui") or []).lower()
        data_model = " ".join(requirements.get("dataModel") or []).lower()
        operational = " ".join(requirements.get("operational") or []).lower()
        dod = " ".join(requirements.get("definitionOfDone") or []).lower()
        self.assertIn("create/list/delete", functional)
        self.assertIn("health endpoint", functional)
        self.assertIn("subscriber notes - dev demo", ui)
        self.assertIn("table", ui)
        self.assertIn("add", ui)
        self.assertTrue("delete" in ui or "deleting" in ui)
        for field in ["id", "subscriber_id", "note_text", "created_at"]:
            self.assertIn(field, data_model)
        for term in ["secrets", "config", "logging", "migrations", "idempotent"]:
            self.assertIn(term, operational)
        self.assertIn("https://josh.xyence.io", dod)
