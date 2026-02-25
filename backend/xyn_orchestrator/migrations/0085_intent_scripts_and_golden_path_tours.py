from django.db import migrations, models
from django.utils import timezone
import uuid


PLATFORM_BUILD_TOUR_SPEC = {
    "profile": "tour",
    "schema_version": 1,
    "title": "Platform Build Tour",
    "description": "Golden path through artifact-first blueprint lifecycle.",
    "category_slug": "xyn_usage",
    "entry": {"route": "/app/artifacts/all"},
    "settings": {"allow_skip": True, "show_progress": True},
    "steps": [
        {
            "id": "open-artifact-explorer",
            "type": "callout",
            "title": "Open Artifact Explorer",
            "body_md": "Artifact Explorer is the system index for draft and canonical artifacts.",
            "route": "/app/artifacts/all",
            "anchor": {"test_id": "artifact-explorer-start-tour", "placement": "bottom"},
        },
        {
            "id": "create-blueprint-draft",
            "type": "callout",
            "title": "Create Blueprint Draft",
            "body_md": "Start in Blueprints / Drafts and create a provisional blueprint artifact.",
            "route": "/app/blueprints/drafts",
            "anchor": {"test_id": "blueprints-start-tour", "placement": "bottom"},
        },
        {
            "id": "edit-draft-provisional",
            "type": "modal",
            "title": "Edit Draft in Provisional State",
            "body_md": "Inspect Artifact Header fields and confirm the Provisional badge before publishing.",
            "route": "/app/blueprints/drafts",
        },
        {
            "id": "publish-version",
            "type": "modal",
            "title": "Publish Blueprint Version",
            "body_md": "Publishing computes validation status and content hash, then promotes the artifact to Canonical.",
            "route": "/app/blueprints/versions",
        },
        {
            "id": "revise-blueprint",
            "type": "modal",
            "title": "Revise Blueprint",
            "body_md": "Use Revise to create a new provisional version in the same family lineage.",
            "route": "/app/blueprints/versions",
        },
        {
            "id": "publish-revision-and-activity",
            "type": "callout",
            "title": "Publish Revision and Review Activity",
            "body_md": "Publish the revised version, then verify governance events in Activity.",
            "route": "/app/activity",
            "anchor": {"test_id": "activity-feed-card", "placement": "bottom"},
        },
    ],
}

ARTICLES_TOUR_SPEC = {
    "profile": "tour",
    "schema_version": 1,
    "title": "Articles Tour",
    "description": "Golden path through article drafting, refinement, publishing, and intent scripts.",
    "category_slug": "xyn_usage",
    "entry": {"route": "/app/artifacts/articles"},
    "settings": {"allow_skip": True, "show_progress": True},
    "steps": [
        {
            "id": "create-article-draft",
            "type": "callout",
            "title": "Create Article Draft",
            "body_md": "Use New Article to create a draft and open the editor directly.",
            "route": "/app/artifacts/articles",
            "anchor": {"test_id": "articles-start-tour", "placement": "bottom"},
        },
        {
            "id": "ai-propose-edits",
            "type": "modal",
            "title": "Propose AI Edits",
            "body_md": "Use contextual refinement to generate diff-based suggestions before applying.",
            "route": "/app/artifacts/articles",
        },
        {
            "id": "publish-and-activity",
            "type": "modal",
            "title": "Publish and Verify Activity",
            "body_md": "Finalize the article, then review the resulting governance activity trail.",
            "route": "/app/activity",
        },
        {
            "id": "generate-intent-script",
            "type": "modal",
            "title": "Generate Intent Script",
            "body_md": "Generate an Intent Script to convert this workflow into scene-by-scene explainer input.",
            "route": "/app/artifacts/articles",
        },
    ],
}


def seed_golden_path_tours(apps, schema_editor):
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

    def upsert_tour(slug: str, title: str, spec: dict):
        defaults = {
            "workspace": workspace,
            "type": artifact_type,
            "article_category": category,
            "title": title,
            "format": "workflow",
            "status": "published",
            "version": 1,
            "visibility": "team",
            "published_at": timezone.now(),
            "workflow_profile": "tour",
            "workflow_spec_json": spec,
            "workflow_state_schema_version": 1,
            "scope_json": {
                "slug": slug,
                "category": "xyn_usage",
                "visibility_type": "authenticated",
                "allowed_roles": [],
                "tags": ["tour", "golden-path", "onboarding"],
            },
            "provenance_json": {},
        }
        Artifact.objects.update_or_create(
            slug=slug,
            type=artifact_type,
            defaults=defaults,
        )

    upsert_tour("platform-build-tour", "Platform Build Tour", PLATFORM_BUILD_TOUR_SPEC)
    upsert_tour("articles-tour", "Articles Tour", ARTICLES_TOUR_SPEC)


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0084_artifact_credibility_fields"),
    ]

    operations = [
        migrations.CreateModel(
            name="IntentScript",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("title", models.CharField(max_length=240)),
                ("scope_type", models.CharField(choices=[("tour", "Tour"), ("artifact", "Artifact"), ("manual", "Manual")], max_length=20)),
                ("scope_ref_id", models.CharField(max_length=120)),
                ("format_version", models.CharField(default="1", max_length=40)),
                ("script_json", models.JSONField(blank=True, default=dict)),
                ("script_text", models.TextField(blank=True, default="")),
                ("status", models.CharField(choices=[("draft", "Draft"), ("final", "Final")], default="draft", max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "artifact",
                    models.ForeignKey(blank=True, null=True, on_delete=models.SET_NULL, related_name="intent_scripts", to="xyn_orchestrator.artifact"),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=models.SET_NULL,
                        related_name="intent_scripts_created",
                        to="xyn_orchestrator.useridentity",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.RunPython(seed_golden_path_tours, migrations.RunPython.noop),
    ]
