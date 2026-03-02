from django.db import migrations


def backfill_surfaces(apps, schema_editor):
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")
    ArtifactSurface = apps.get_model("xyn_orchestrator", "ArtifactSurface")
    ArtifactRuntimeRole = apps.get_model("xyn_orchestrator", "ArtifactRuntimeRole")

    articles = list(Artifact.objects.filter(type__slug="article").order_by("updated_at", "created_at"))
    workflows = list(Artifact.objects.filter(type__slug="workflow").order_by("updated_at", "created_at"))

    if articles:
        host = articles[-1]
        ArtifactSurface.objects.update_or_create(
            artifact_id=host.id,
            key="articles_hub",
            defaults={
                "title": "Articles",
                "description": "Articles authoring hub",
                "surface_kind": "editor",
                "route": "/app/a/articles",
                "nav_visibility": "always",
                "nav_label": "Articles",
                "nav_icon": "BookOpen",
                "nav_group": "Build",
                "renderer": {"type": "ui_component_ref", "payload": {"component_key": "articles.index"}},
                "context": {"required": [], "bindings": {}},
                "permissions": {"required_roles": ["platform_architect", "platform_admin"]},
                "sort_order": 200,
            },
        )

    if workflows:
        host = workflows[-1]
        ArtifactSurface.objects.update_or_create(
            artifact_id=host.id,
            key="workflows_hub",
            defaults={
                "title": "Workflows",
                "description": "Workflow authoring hub",
                "surface_kind": "editor",
                "route": "/app/a/workflows",
                "nav_visibility": "always",
                "nav_label": "Workflows",
                "nav_icon": "Route",
                "nav_group": "Build",
                "renderer": {"type": "ui_component_ref", "payload": {"component_key": "workflows.index"}},
                "context": {"required": [], "bindings": {}},
                "permissions": {"required_roles": ["platform_architect", "platform_admin"]},
                "sort_order": 210,
            },
        )

    for artifact in articles:
        ArtifactSurface.objects.update_or_create(
            artifact_id=artifact.id,
            key="article_editor",
            defaults={
                "title": "Article editor",
                "description": "Artifact-backed article draft editor",
                "surface_kind": "editor",
                "route": f"/app/a/articles/{artifact.id}",
                "nav_visibility": "contextual",
                "nav_label": "",
                "nav_icon": "",
                "nav_group": "Content",
                "renderer": {"type": "ui_component_ref", "payload": {"component_key": "articles.draft_editor"}},
                "context": {"required": ["artifact"], "bindings": {"artifactId": str(artifact.id)}},
                "permissions": {"required_roles": ["platform_architect", "platform_admin"]},
                "sort_order": 10,
            },
        )

    for artifact in workflows:
        ArtifactSurface.objects.update_or_create(
            artifact_id=artifact.id,
            key="workflow_editor",
            defaults={
                "title": "Workflow editor",
                "description": "Artifact-backed workflow editor",
                "surface_kind": "editor",
                "route": f"/app/a/workflows/{artifact.id}",
                "nav_visibility": "contextual",
                "nav_group": "Automation",
                "renderer": {"type": "ui_component_ref", "payload": {"component_key": "workflows.editor"}},
                "context": {"required": ["artifact"], "bindings": {"workflowId": str(artifact.id)}},
                "permissions": {"required_roles": ["platform_architect", "platform_admin"]},
                "sort_order": 20,
            },
        )
        ArtifactSurface.objects.update_or_create(
            artifact_id=artifact.id,
            key="workflow_visualizer",
            defaults={
                "title": "Workflow visualizer",
                "description": "Visual workflow graph surface",
                "surface_kind": "visualizer",
                "route": f"/app/a/workflows/{artifact.id}/graph",
                "nav_visibility": "contextual",
                "nav_group": "Automation",
                "renderer": {"type": "workflow_visualizer", "payload": {}},
                "context": {"required": ["artifact"], "bindings": {"workflowId": str(artifact.id)}},
                "permissions": {"required_roles": ["platform_architect", "platform_admin"]},
                "sort_order": 30,
            },
        )
        ArtifactRuntimeRole.objects.update_or_create(
            artifact_id=artifact.id,
            role_kind="route_provider",
            defaults={
                "enabled": True,
                "spec": {
                    "surface_keys": ["workflow_editor", "workflow_visualizer"],
                    "routes": [f"/app/a/workflows/{artifact.id}", f"/app/a/workflows/{artifact.id}/graph"],
                },
            },
        )


def noop(apps, schema_editor):
    return


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0090_artifact_surfaces_runtime_roles"),
    ]

    operations = [
        migrations.RunPython(backfill_surfaces, noop),
    ]
