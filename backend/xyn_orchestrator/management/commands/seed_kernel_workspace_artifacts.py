from __future__ import annotations

from django.core.management.base import BaseCommand

from xyn_orchestrator.models import Artifact, ArtifactType, Workspace, WorkspaceArtifactBinding


class Command(BaseCommand):
    help = "Bind kernel-loadable artifacts (workbench, xyn runtime, xyn-api, xyn-ui, hello app, ems) into a workspace."

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
                "slug": "core.workbench",
                "title": "Workbench",
                "manifest_ref": "registry/modules/workbench.artifact.manifest.json",
            },
            {
                "slug": "core.xyn-runtime",
                "title": "Xyn Runtime",
                "manifest_ref": "registry/modules/xyn-runtime.artifact.manifest.json",
            },
            {
                "slug": "xyn-api",
                "title": "xyn-api",
                "manifest_ref": "registry/modules/xyn-api.artifact.manifest.json",
            },
            {
                "slug": "xyn-ui",
                "title": "xyn-ui",
                "manifest_ref": "registry/modules/xyn-ui.artifact.manifest.json",
            },
            {
                "slug": "hello-app",
                "title": "Hello App",
                "manifest_ref": "xyn-ui/apps/hello-artifact/artifact.manifest.json",
            },
            {
                "slug": "ems",
                "title": "EMS",
                "manifest_ref": "apps/ems-artifact/artifact.manifest.json",
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

        # Normalize legacy slug so previously installed EMS-lite maps to EMS manifest identity.
        legacy_ems = Artifact.objects.filter(workspace=workspace, slug="ems-lite").order_by("-updated_at", "-created_at").first()
        canonical_ems = Artifact.objects.filter(workspace=workspace, slug="ems").order_by("-updated_at", "-created_at").first()
        if legacy_ems and canonical_ems is None:
            legacy_ems.slug = "ems"
            legacy_ems.title = "EMS"
            scope = dict(legacy_ems.scope_json or {})
            scope["slug"] = "ems"
            scope["manifest_ref"] = "apps/ems-artifact/artifact.manifest.json"
            legacy_ems.scope_json = scope
            legacy_ems.save(update_fields=["slug", "title", "scope_json", "updated_at"])

        self.stdout.write(
            self.style.SUCCESS(
                f"workspace={workspace.slug} artifacts_created={created_artifacts} bindings_created={created_bindings}"
            )
        )
