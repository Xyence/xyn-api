from __future__ import annotations

from django.core.management.base import BaseCommand

from xyn_orchestrator.models import Artifact, ArtifactRevision, ArtifactType, Workspace


INSTANCE_PAYLOAD = {
    "schema_version": "xyn.instance.v1",
    "name": "xyn-ec2-demo",
    "kind": "ec2",
    "status": "running",
    "network": {
        "public_ipv4": "54.200.65.160",
    },
    "notes": {
        "source": "manual_bootstrap",
    },
}


class Command(BaseCommand):
    help = "Create or update the demo instance artifact (xyn-ec2-demo)."

    def add_arguments(self, parser):
        parser.add_argument("--workspace", default="platform-builder", help="Workspace slug (default: platform-builder)")
        parser.add_argument("--slug", default="xyn-ec2-demo", help="Instance artifact slug")
        parser.add_argument("--ip", default="54.200.65.160", help="Public IPv4 to record")

    def handle(self, *args, **options):
        workspace_slug = str(options.get("workspace") or "platform-builder").strip()
        slug = str(options.get("slug") or "xyn-ec2-demo").strip()
        ip = str(options.get("ip") or "54.200.65.160").strip()

        workspace = Workspace.objects.filter(slug=workspace_slug).order_by("created_at").first()
        if workspace is None:
            workspace = Workspace.objects.order_by("created_at").first()
        if workspace is None:
            workspace = Workspace.objects.create(slug="default-workspace", name="Default Workspace")

        artifact_type, _ = ArtifactType.objects.get_or_create(
            slug="instance",
            defaults={
                "name": "Instance",
                "description": "Deployable host/runtime instance descriptor artifact.",
                "icon": "Server",
                "schema_json": {
                    "schema_version": "xyn.instance.v1",
                    "kind": ["ec2", "generic_host"],
                    "status": ["running", "stopped", "unknown"],
                },
            },
        )

        payload = dict(INSTANCE_PAYLOAD)
        payload["name"] = slug
        payload["network"] = {"public_ipv4": ip}

        artifact = Artifact.objects.filter(type=artifact_type, slug=slug).order_by("-updated_at", "-created_at").first()
        created = artifact is None
        if created:
            artifact = Artifact.objects.create(
                workspace=workspace,
                type=artifact_type,
                title=slug,
                slug=slug,
                summary="Demo EC2 instance descriptor",
                schema_version="xyn.instance.v1",
                status="published",
                visibility="team",
                scope_json={"slug": slug, "summary": "Demo EC2 instance descriptor"},
                provenance_json={"source_system": "manual_import", "source_id": slug},
            )
            ArtifactRevision.objects.create(artifact=artifact, revision_number=1, content_json=payload)
            self.stdout.write(self.style.SUCCESS(f"Created instance artifact {slug} in workspace {workspace.slug}"))
            return

        fields = []
        if artifact.workspace_id != workspace.id:
            artifact.workspace = workspace
            fields.append("workspace")
        if artifact.title != slug:
            artifact.title = slug
            fields.append("title")
        if artifact.status != "published":
            artifact.status = "published"
            fields.append("status")
        if artifact.schema_version != "xyn.instance.v1":
            artifact.schema_version = "xyn.instance.v1"
            fields.append("schema_version")
        if fields:
            fields.append("updated_at")
            artifact.save(update_fields=fields)

        latest = ArtifactRevision.objects.filter(artifact=artifact).order_by("-revision_number").first()
        latest_payload = latest.content_json if latest and isinstance(latest.content_json, dict) else {}
        if latest_payload != payload:
            ArtifactRevision.objects.create(
                artifact=artifact,
                revision_number=int(getattr(latest, "revision_number", 0) or 0) + 1,
                content_json=payload,
            )
            self.stdout.write(self.style.SUCCESS(f"Updated instance artifact {slug} with new revision"))
        else:
            self.stdout.write(self.style.SUCCESS(f"Instance artifact {slug} already up to date"))
