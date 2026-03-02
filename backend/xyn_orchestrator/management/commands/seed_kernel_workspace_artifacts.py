from __future__ import annotations

from django.core.management.base import BaseCommand

from xyn_orchestrator.models import Artifact, ArtifactType, Workspace, WorkspaceArtifactBinding


class Command(BaseCommand):
    help = "Bind kernel-loadable artifacts (xyn-api, xyn-ui, hello app, ems-lite) into a workspace."

    def add_arguments(self, parser):
        parser.add_argument("--workspace-slug", default="platform-builder")
        parser.add_argument("--workspace-name", default="Platform Builder")

    def handle(self, *args, **options):
        workspace_slug = str(options.get("workspace_slug") or "platform-builder").strip() or "platform-builder"
        workspace_name = str(options.get("workspace_name") or "Platform Builder").strip() or "Platform Builder"

        workspace, _ = Workspace.objects.get_or_create(
            slug=workspace_slug,
            defaults={"name": workspace_name, "description": "Seed kernel workspace"},
        )
        artifact_type, _ = ArtifactType.objects.get_or_create(
            slug="module",
            defaults={"name": "Module", "description": "Kernel-loadable module artifact."},
        )

        specs = [
            {
                "slug": "xyn-api",
                "title": "xyn-api",
                "manifest_ref": "xyn-api/artifact.manifest.json",
            },
            {
                "slug": "xyn-ui",
                "title": "xyn-ui",
                "manifest_ref": "xyn-ui/artifact.manifest.json",
            },
            {
                "slug": "hello-app",
                "title": "Hello App",
                "manifest_ref": "xyn-ui/apps/hello-artifact/artifact.manifest.json",
            },
            {
                "slug": "ems-lite",
                "title": "EMS-lite",
                "manifest_ref": "artifacts/ems-lite/artifact.manifest.json",
            },
        ]

        created_artifacts = 0
        created_bindings = 0
        for spec in specs:
            artifact, created = Artifact.objects.get_or_create(
                workspace=workspace,
                slug=spec["slug"],
                defaults={
                    "type": artifact_type,
                    "title": spec["title"],
                    "status": "published",
                    "visibility": "team",
                    "scope_json": {
                        "slug": spec["slug"],
                        "manifest_ref": spec["manifest_ref"],
                        "summary": f"Kernel-loaded artifact for {spec['title']}",
                    },
                    "provenance_json": {
                        "source_system": "seed-kernel",
                        "source_id": spec["slug"],
                    },
                },
            )
            if created:
                created_artifacts += 1
            else:
                scope = dict(artifact.scope_json or {})
                if scope.get("manifest_ref") != spec["manifest_ref"]:
                    scope["manifest_ref"] = spec["manifest_ref"]
                    artifact.scope_json = scope
                    artifact.save(update_fields=["scope_json", "updated_at"])

            _, binding_created = WorkspaceArtifactBinding.objects.get_or_create(
                workspace=workspace,
                artifact=artifact,
                defaults={
                    "enabled": True,
                    "installed_state": "installed",
                    "config_ref": None,
                },
            )
            if binding_created:
                created_bindings += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"workspace={workspace.slug} artifacts_created={created_artifacts} bindings_created={created_bindings}"
            )
        )
