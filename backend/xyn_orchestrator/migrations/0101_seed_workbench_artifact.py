from django.db import migrations


def seed_workbench_artifact(apps, schema_editor):
    Workspace = apps.get_model("xyn_orchestrator", "Workspace")
    ArtifactType = apps.get_model("xyn_orchestrator", "ArtifactType")
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")
    WorkspaceArtifactBinding = apps.get_model("xyn_orchestrator", "WorkspaceArtifactBinding")

    module_type, _ = ArtifactType.objects.get_or_create(
        slug="module",
        defaults={"name": "Module", "description": "Kernel-loadable module artifact."},
    )

    host_workspace = Workspace.objects.filter(slug="platform-builder").first()
    if host_workspace is None:
        host_workspace = Workspace.objects.order_by("created_at").first()
    if host_workspace is None:
        host_workspace = Workspace.objects.create(slug="platform-builder", name="Platform Builder")

    artifact = Artifact.objects.filter(slug="core.workbench").order_by("-updated_at", "-created_at").first()
    if artifact is None:
        artifact = Artifact.objects.create(
            workspace=host_workspace,
            type=module_type,
            title="Workbench",
            slug="core.workbench",
            status="published",
            visibility="team",
            summary="Console-first, panel-based runtime landing experience.",
            scope_json={
                "slug": "core.workbench",
                "manifest_ref": "registry/modules/workbench.artifact.manifest.json",
                "summary": "Console-first, panel-based runtime landing experience.",
            },
            provenance_json={"source_system": "seed-kernel", "source_id": "core.workbench"},
        )
    else:
        scope = dict(artifact.scope_json or {})
        scope["slug"] = "core.workbench"
        scope["manifest_ref"] = "registry/modules/workbench.artifact.manifest.json"
        artifact.scope_json = scope
        artifact.save(update_fields=["scope_json", "updated_at"])

    # Backfill/install-by-default behavior: bind the workbench artifact into all existing workspaces.
    for workspace in Workspace.objects.all():
        WorkspaceArtifactBinding.objects.get_or_create(
            workspace=workspace,
            artifact=artifact,
            defaults={"enabled": True, "installed_state": "installed", "config_ref": None},
        )


def noop(apps, schema_editor):
    return None


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0100_normalize_artifact_manifest_refs"),
    ]

    operations = [
        migrations.RunPython(seed_workbench_artifact, noop),
    ]

