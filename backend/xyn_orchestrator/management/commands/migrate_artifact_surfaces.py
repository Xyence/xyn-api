from __future__ import annotations

from django.core.management.base import BaseCommand
from django.db import transaction

from xyn_orchestrator.models import Artifact, ArtifactRuntimeRole, ArtifactSurface


class Command(BaseCommand):
    help = "Backfill article/workflow artifact surfaces and runtime roles."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Preview without writes")

    def handle(self, *args, **options):
        dry_run = bool(options.get("dry_run"))

        articles = list(Artifact.objects.filter(type__slug="article").order_by("updated_at"))
        workflows = list(Artifact.objects.filter(type__slug="workflow").order_by("updated_at"))

        created_surfaces = 0
        updated_surfaces = 0
        created_roles = 0
        updated_roles = 0

        @transaction.atomic
        def _apply():
            nonlocal created_surfaces, updated_surfaces, created_roles, updated_roles

            article_hub_host = articles[-1] if articles else None
            workflow_hub_host = workflows[-1] if workflows else None

            if article_hub_host:
                obj, created = ArtifactSurface.objects.update_or_create(
                    artifact=article_hub_host,
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
                if created:
                    created_surfaces += 1
                else:
                    updated_surfaces += 1

            if workflow_hub_host:
                obj, created = ArtifactSurface.objects.update_or_create(
                    artifact=workflow_hub_host,
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
                if created:
                    created_surfaces += 1
                else:
                    updated_surfaces += 1

            for artifact in articles:
                surface, created = ArtifactSurface.objects.update_or_create(
                    artifact=artifact,
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
                if created:
                    created_surfaces += 1
                else:
                    updated_surfaces += 1

            for artifact in workflows:
                surface, created = ArtifactSurface.objects.update_or_create(
                    artifact=artifact,
                    key="workflow_editor",
                    defaults={
                        "title": "Workflow editor",
                        "description": "Artifact-backed workflow editor",
                        "surface_kind": "editor",
                        "route": f"/app/a/workflows/{artifact.id}",
                        "nav_visibility": "contextual",
                        "nav_label": "",
                        "nav_icon": "",
                        "nav_group": "Automation",
                        "renderer": {"type": "ui_component_ref", "payload": {"component_key": "workflows.editor"}},
                        "context": {"required": ["artifact"], "bindings": {"workflowId": str(artifact.id)}},
                        "permissions": {"required_roles": ["platform_architect", "platform_admin"]},
                        "sort_order": 20,
                    },
                )
                if created:
                    created_surfaces += 1
                else:
                    updated_surfaces += 1

                viz, created = ArtifactSurface.objects.update_or_create(
                    artifact=artifact,
                    key="workflow_visualizer",
                    defaults={
                        "title": "Workflow visualizer",
                        "description": "Visual workflow graph surface",
                        "surface_kind": "visualizer",
                        "route": f"/app/a/workflows/{artifact.id}/graph",
                        "nav_visibility": "contextual",
                        "nav_label": "",
                        "nav_icon": "",
                        "nav_group": "Automation",
                        "renderer": {"type": "workflow_visualizer", "payload": {}},
                        "context": {"required": ["artifact"], "bindings": {"workflowId": str(artifact.id)}},
                        "permissions": {"required_roles": ["platform_architect", "platform_admin"]},
                        "sort_order": 30,
                    },
                )
                if created:
                    created_surfaces += 1
                else:
                    updated_surfaces += 1

                role, created = ArtifactRuntimeRole.objects.update_or_create(
                    artifact=artifact,
                    role_kind="route_provider",
                    defaults={
                        "enabled": True,
                        "spec": {
                            "surface_keys": ["workflow_editor", "workflow_visualizer"],
                            "routes": [f"/app/a/workflows/{artifact.id}", f"/app/a/workflows/{artifact.id}/graph"],
                        },
                    },
                )
                if created:
                    created_roles += 1
                else:
                    updated_roles += 1

        if dry_run:
            self.stdout.write(self.style.WARNING(f"dry-run: would process {len(articles)} articles and {len(workflows)} workflows"))
            return

        _apply()

        self.stdout.write(
            self.style.SUCCESS(
                f"artifact surfaces migration complete: surfaces created={created_surfaces}, updated={updated_surfaces}; "
                f"runtime roles created={created_roles}, updated={updated_roles}"
            )
        )
