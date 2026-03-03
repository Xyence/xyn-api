from django.db import migrations


def normalize_manifest_refs(apps, schema_editor):
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")
    targets = {
        "core.authn-jwt": "registry/modules/authn-jwt.artifact.manifest.json",
        "ems": "registry/modules/ems.artifact.manifest.json",
    }
    for slug, manifest_ref in targets.items():
        artifact = Artifact.objects.filter(slug=slug).first()
        if artifact is None:
            continue
        scope = dict(artifact.scope_json or {})
        scope["manifest_ref"] = manifest_ref
        artifact.scope_json = scope
        artifact.save(update_fields=["scope_json", "updated_at"])


def noop(apps, schema_editor):
    return None


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0099_workspace_app_instance"),
    ]

    operations = [
        migrations.RunPython(normalize_manifest_refs, noop),
    ]
