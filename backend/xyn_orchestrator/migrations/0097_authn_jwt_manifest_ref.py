from django.db import migrations


def align_authn_jwt_manifest_ref(apps, schema_editor):
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

    canonical_slug = "core.authn-jwt"
    manifest_ref = "xyn-api/backend/registry/modules/authn-jwt.artifact.manifest.json"

    # Phase hardening note: keep manifest.artifact.id aligned to canonical slug.
    artifact = Artifact.objects.filter(slug=canonical_slug).order_by("-updated_at", "-created_at").first()
    if artifact is None:
        legacy = Artifact.objects.filter(slug="authn-jwt").order_by("-updated_at", "-created_at").first()
        if legacy is not None:
            legacy.slug = canonical_slug
            scope = dict(legacy.scope_json or {})
            scope["slug"] = canonical_slug
            legacy.scope_json = scope
            legacy.save(update_fields=["slug", "scope_json", "updated_at"])
            artifact = legacy

    if artifact is None:
        artifact = Artifact.objects.create(
            workspace=workspace,
            type=module_type,
            title="core.authn-jwt",
            slug=canonical_slug,
            status="published",
            visibility="team",
            summary="JWT authentication capability artifact.",
            scope_json={
                "slug": canonical_slug,
                "manifest_ref": manifest_ref,
                "summary": "JWT authentication capability artifact.",
            },
            provenance_json={"source_system": "seed-kernel", "source_id": canonical_slug},
        )

    scope = dict(artifact.scope_json or {})
    changed = False
    if str(scope.get("slug") or "").strip() != canonical_slug:
        scope["slug"] = canonical_slug
        changed = True
    if str(scope.get("manifest_ref") or "").strip() != manifest_ref:
        scope["manifest_ref"] = manifest_ref
        changed = True
    if changed:
        artifact.scope_json = scope
        artifact.save(update_fields=["scope_json", "updated_at"])


def noop(apps, schema_editor):
    return


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0096_workspace_oidc_policy"),
    ]

    operations = [
        migrations.RunPython(align_authn_jwt_manifest_ref, noop),
    ]
