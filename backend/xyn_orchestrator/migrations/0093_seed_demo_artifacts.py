from django.db import migrations


def seed_demo_artifacts(apps, schema_editor):
    Workspace = apps.get_model("xyn_orchestrator", "Workspace")
    ArtifactType = apps.get_model("xyn_orchestrator", "ArtifactType")
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")

    workspace = Workspace.objects.filter(slug="platform-builder").first()
    if workspace is None:
        workspace = Workspace.objects.order_by("created_at").first()
    if workspace is None:
        workspace = Workspace.objects.create(slug="platform-builder", name="Platform Builder")

    module_type, _ = ArtifactType.objects.get_or_create(
        slug="module",
        defaults={"name": "Module", "description": "Kernel-loadable module artifact."},
    )

    # Normalize legacy hello slug to the manifest identity `hello-app`.
    legacy_hello = Artifact.objects.filter(slug="xyn-hello-app").order_by("-updated_at", "-created_at").first()
    canonical_hello = Artifact.objects.filter(slug="hello-app").order_by("-updated_at", "-created_at").first()
    if legacy_hello and canonical_hello is None:
        scope = dict(legacy_hello.scope_json or {})
        if str(scope.get("slug") or "").strip() in {"", "xyn-hello-app"}:
            scope["slug"] = "hello-app"
        legacy_hello.slug = "hello-app"
        legacy_hello.scope_json = scope
        legacy_hello.save(update_fields=["slug", "scope_json", "updated_at"])
        canonical_hello = legacy_hello

    hello, _ = Artifact.objects.get_or_create(
        slug="hello-app",
        defaults={
            "workspace": workspace,
            "type": module_type,
            "title": "Hello App",
            "status": "published",
            "visibility": "team",
            "summary": "Kernel-loaded artifact for Hello App",
            "scope_json": {
                "slug": "hello-app",
                "manifest_ref": "xyn-ui/apps/hello-artifact/artifact.manifest.json",
                "summary": "Kernel-loaded artifact for Hello App",
            },
            "provenance_json": {"source_system": "seed-kernel", "source_id": "hello-app"},
        },
    )
    hello_scope = dict(hello.scope_json or {})
    if str(hello_scope.get("manifest_ref") or "").strip() != "xyn-ui/apps/hello-artifact/artifact.manifest.json":
        hello_scope["manifest_ref"] = "xyn-ui/apps/hello-artifact/artifact.manifest.json"
    if str(hello_scope.get("slug") or "").strip() in {"", "xyn-hello-app"}:
        hello_scope["slug"] = "hello-app"
    if hello_scope != (hello.scope_json or {}):
        hello.scope_json = hello_scope
        hello.save(update_fields=["scope_json", "updated_at"])

    Artifact.objects.get_or_create(
        slug="ems-lite",
        defaults={
            "workspace": workspace,
            "type": module_type,
            "title": "EMS-lite",
            "status": "published",
            "visibility": "team",
            "summary": "Minimal asset management app artifact for demo workspaces.",
            "scope_json": {
                "slug": "ems-lite",
                "manifest_ref": "artifacts/ems-lite/artifact.manifest.json",
                "summary": "Minimal asset management app artifact for demo workspaces.",
            },
            "provenance_json": {"source_system": "seed-kernel", "source_id": "ems-lite"},
        },
    )


def noop(apps, schema_editor):
    return


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0092_workspace_artifact_bindings"),
    ]

    operations = [
        migrations.RunPython(seed_demo_artifacts, noop),
    ]
