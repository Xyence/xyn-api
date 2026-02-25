from django.db import migrations
from django.utils import timezone


TOUR_SPEC = {
    "profile": "tour",
    "schema_version": 1,
    "title": "Deploy Subscriber Notes",
    "description": "Guided end-to-end onboarding flow for draft to deployment lifecycle.",
    "category_slug": "xyn_usage",
    "entry": {"route": "/app/drafts"},
    "settings": {"allow_skip": True, "show_progress": True},
    "steps": [
        {
            "id": "intro",
            "type": "modal",
            "title": "Drafts are where intent becomes structure",
            "body_md": "Draft Sessions capture intent before publishing build artifacts.",
            "route": "/app/drafts",
            "ui": {"block_interaction": False, "allow_back": False},
        },
        {
            "id": "create-draft",
            "type": "action",
            "title": "Create a new draft session",
            "body_md": "Create a deterministic demo draft used in this walkthrough.",
            "route": "/app/drafts",
            "anchor": {"test_id": "draft-create", "placement": "bottom"},
            "action_id": "blueprint.create_demo_draft",
            "params": {
                "title": "subscriber-notes-demo",
                "namespace": "core",
                "project_key": "core.subscriber-notes-demo",
                "initial_prompt": "Create a Subscriber Notes app for a telecom support team.",
            },
            "success_toast": "Demo draft prepared.",
        },
        {
            "id": "promote",
            "type": "callout",
            "title": "Promote draft to blueprint",
            "body_md": "Use Submit as Blueprint to create a governed artifact.",
            "route": "/app/drafts",
            "anchor": {"test_id": "draft-promote", "placement": "bottom"},
        },
        {
            "id": "release-plan",
            "type": "callout",
            "title": "Create a release plan",
            "body_md": "Open Release Plans and create one for your target environment.",
            "route": "/app/release-plans",
            "anchor": {"test_id": "release-plan-create", "placement": "bottom"},
        },
        {
            "id": "instance",
            "type": "callout",
            "title": "Choose a development instance",
            "body_md": "Pick an available instance, then return to Release Plans.",
            "route": "/app/instances",
            "anchor": {"test_id": "instance-select", "placement": "bottom"},
        },
        {
            "id": "deploy",
            "type": "callout",
            "title": "Deploy the plan",
            "body_md": "Run deployment from the release plan detail.",
            "route": "/app/release-plans",
            "anchor": {"test_id": "release-plan-deploy", "placement": "bottom"},
        },
        {
            "id": "observe",
            "type": "callout",
            "title": "Observe logs and artifacts",
            "body_md": "Use Runs to inspect execution output and troubleshoot issues.",
            "route": "/app/runs",
            "anchor": {"test_id": "run-artifacts", "placement": "bottom"},
        },
    ],
}


def seed_default_tour(apps, schema_editor):
    Workspace = apps.get_model("xyn_orchestrator", "Workspace")
    ArtifactType = apps.get_model("xyn_orchestrator", "ArtifactType")
    ArticleCategory = apps.get_model("xyn_orchestrator", "ArticleCategory")
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")

    workspace, _ = Workspace.objects.get_or_create(
        slug="platform-builder",
        defaults={"name": "Platform Builder", "description": "Platform governance and operator documentation"},
    )
    category, _ = ArticleCategory.objects.get_or_create(
        slug="xyn_usage",
        defaults={"name": "Xyn Usage", "description": "Guided tours for Xyn usage and onboarding", "enabled": True},
    )
    artifact_type, _ = ArtifactType.objects.get_or_create(
        slug="workflow",
        defaults={
            "name": "Workflow",
            "description": "Governed workflow artifacts (tour profile)",
            "icon": "Route",
            "schema_json": {"profile": ["tour"]},
        },
    )
    exists = Artifact.objects.filter(type=artifact_type, workspace=workspace, slug="deploy-subscriber-notes").first()
    if exists:
        return
    Artifact.objects.create(
        workspace=workspace,
        type=artifact_type,
        article_category=category,
        title="Deploy Subscriber Notes",
        slug="deploy-subscriber-notes",
        format="workflow",
        status="published",
        version=1,
        visibility="team",
        published_at=timezone.now(),
        workflow_profile="tour",
        workflow_spec_json=TOUR_SPEC,
        workflow_state_schema_version=1,
        scope_json={
            "slug": "deploy-subscriber-notes",
            "category": "xyn_usage",
            "visibility_type": "authenticated",
            "allowed_roles": [],
            "tags": ["tour", "onboarding"],
        },
        provenance_json={},
    )


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0079_workflow_artifact_and_runs"),
    ]

    operations = [
        migrations.RunPython(seed_default_tour, migrations.RunPython.noop),
    ]
