from django.db import migrations


def seed_public_site_artifact(apps, schema_editor):
    Workspace = apps.get_model("xyn_orchestrator", "Workspace")
    ArtifactType = apps.get_model("xyn_orchestrator", "ArtifactType")
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")

    module_type, _ = ArtifactType.objects.get_or_create(
        slug="module",
        defaults={"name": "Module", "description": "Kernel-loadable module artifact."},
    )

    host_workspace = Workspace.objects.filter(slug="platform-builder").first()
    if host_workspace is None:
        host_workspace = Workspace.objects.order_by("created_at").first()
    if host_workspace is None:
        host_workspace = Workspace.objects.create(slug="platform-builder", name="Platform Builder")

    artifact = Artifact.objects.filter(slug="core.public-site").order_by("-updated_at", "-created_at").first()
    if artifact is None:
        Artifact.objects.create(
            workspace=host_workspace,
            type=module_type,
            title="Public Site",
            slug="core.public-site",
            status="published",
            visibility="team",
            summary="Public, unauthenticated landing surface for Xyn.",
            scope_json={
                "slug": "core.public-site",
                "manifest_ref": "registry/modules/public-site.artifact.manifest.json",
                "summary": "Public, unauthenticated landing surface for Xyn.",
            },
            provenance_json={"source_system": "seed-kernel", "source_id": "core.public-site"},
        )
        return

    changed = False
    if str(artifact.title or "").strip() != "Public Site":
        artifact.title = "Public Site"
        changed = True
    scope = dict(artifact.scope_json or {})
    if str(scope.get("slug") or "").strip() != "core.public-site":
        scope["slug"] = "core.public-site"
        changed = True
    if str(scope.get("manifest_ref") or "").strip() != "registry/modules/public-site.artifact.manifest.json":
        scope["manifest_ref"] = "registry/modules/public-site.artifact.manifest.json"
        changed = True
    if changed:
        artifact.scope_json = scope
        artifact.save(update_fields=["title", "scope_json", "updated_at"])


def noop(apps, schema_editor):
    return None


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0101_seed_workbench_artifact"),
    ]

    operations = [
        migrations.RunPython(seed_public_site_artifact, noop),
    ]

