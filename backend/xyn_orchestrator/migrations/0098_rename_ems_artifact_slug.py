from django.db import migrations


def align_ems_artifact_identity(apps, schema_editor):
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

    canonical_slug = "ems"
    canonical_title = "EMS"
    manifest_ref = "apps/ems-artifact/artifact.manifest.json"
    summary = "Enterprise Management System demo app artifact for workspace demos."

    canonical = Artifact.objects.filter(slug=canonical_slug).order_by("-updated_at", "-created_at").first()
    legacy = Artifact.objects.filter(slug="ems-lite").order_by("-updated_at", "-created_at").first()
    target = canonical or legacy

    if target is None:
        target = Artifact.objects.create(
            workspace=workspace,
            type=module_type,
            title=canonical_title,
            slug=canonical_slug,
            status="published",
            visibility="team",
            summary=summary,
            scope_json={
                "slug": canonical_slug,
                "manifest_ref": manifest_ref,
                "summary": summary,
            },
            provenance_json={"source_system": "seed-kernel", "source_id": canonical_slug},
        )

    changed_fields = []
    if target.slug != canonical_slug:
        target.slug = canonical_slug
        changed_fields.append("slug")
    if target.title != canonical_title:
        target.title = canonical_title
        changed_fields.append("title")
    if (target.summary or "").strip() != summary:
        target.summary = summary
        changed_fields.append("summary")

    scope = dict(target.scope_json or {})
    if str(scope.get("slug") or "").strip() != canonical_slug:
        scope["slug"] = canonical_slug
    if str(scope.get("manifest_ref") or "").strip() != manifest_ref:
        scope["manifest_ref"] = manifest_ref
    if str(scope.get("summary") or "").strip() != summary:
        scope["summary"] = summary
    if scope != (target.scope_json or {}):
        target.scope_json = scope
        changed_fields.append("scope_json")

    if changed_fields:
        target.save(update_fields=[*changed_fields, "updated_at"])


def noop(apps, schema_editor):
    return


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0097_authn_jwt_manifest_ref"),
    ]

    operations = [
        migrations.RunPython(align_ems_artifact_identity, noop),
    ]
