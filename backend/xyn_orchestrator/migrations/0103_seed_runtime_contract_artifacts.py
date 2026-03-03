from django.db import migrations


def seed_runtime_contract_artifacts(apps, schema_editor):
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

    specs = [
        {
            "slug": "xyn-api",
            "title": "xyn-api",
            "summary": "Deployable Xyn API runtime artifact.",
            "manifest_ref": "registry/modules/xyn-api.artifact.manifest.json",
            "bind_all_workspaces": True,
        },
        {
            "slug": "xyn-ui",
            "title": "xyn-ui",
            "summary": "Deployable Xyn UI runtime artifact.",
            "manifest_ref": "registry/modules/xyn-ui.artifact.manifest.json",
            "bind_all_workspaces": True,
        },
        {
            "slug": "core.xyn-runtime",
            "title": "Xyn Runtime",
            "summary": "Meta-artifact orchestrator for self-deploying Xyn runtime.",
            "manifest_ref": "registry/modules/xyn-runtime.artifact.manifest.json",
            "bind_all_workspaces": False,
        },
    ]

    for spec in specs:
        artifact = Artifact.objects.filter(slug=spec["slug"]).order_by("-updated_at", "-created_at").first()
        if artifact is None:
            artifact = Artifact.objects.create(
                workspace=host_workspace,
                type=module_type,
                title=spec["title"],
                slug=spec["slug"],
                status="published",
                visibility="team",
                summary=spec["summary"],
                scope_json={
                    "slug": spec["slug"],
                    "manifest_ref": spec["manifest_ref"],
                    "summary": spec["summary"],
                },
                provenance_json={"source_system": "seed-kernel", "source_id": spec["slug"]},
            )
        else:
            scope = dict(artifact.scope_json or {})
            scope["slug"] = spec["slug"]
            scope["manifest_ref"] = spec["manifest_ref"]
            changed = False
            if str(artifact.title or "") != spec["title"]:
                artifact.title = spec["title"]
                changed = True
            if str(artifact.summary or "") != spec["summary"]:
                artifact.summary = spec["summary"]
                changed = True
            if scope != (artifact.scope_json or {}):
                artifact.scope_json = scope
                changed = True
            if changed:
                artifact.save(update_fields=["title", "summary", "scope_json", "updated_at"])

        if spec["bind_all_workspaces"]:
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
        ("xyn_orchestrator", "0102_seed_public_site_artifact"),
    ]

    operations = [
        migrations.RunPython(seed_runtime_contract_artifacts, noop),
    ]

