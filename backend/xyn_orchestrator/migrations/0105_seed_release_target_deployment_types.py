from django.db import migrations


def seed_artifact_types(apps, schema_editor):
    ArtifactType = apps.get_model("xyn_orchestrator", "ArtifactType")
    ArtifactType.objects.get_or_create(
        slug="release_spec",
        defaults={
            "name": "Release Spec",
            "description": "Deployment release specification artifact.",
            "icon": "Rocket",
            "schema_json": {"schema_version": "xyn.release_spec.v1"},
        },
    )
    ArtifactType.objects.get_or_create(
        slug="target",
        defaults={
            "name": "Target",
            "description": "Deployment target/provider artifact.",
            "icon": "Target",
            "schema_json": {"schema_version": "xyn.target.v1"},
        },
    )
    ArtifactType.objects.get_or_create(
        slug="deployment",
        defaults={
            "name": "Deployment",
            "description": "Immutable deployment execution record artifact.",
            "icon": "FileClock",
            "schema_json": {"schema_version": "xyn.deployment.v1"},
        },
    )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0104_instance_artifact_type_and_demo_seed"),
    ]

    operations = [
        migrations.RunPython(seed_artifact_types, noop_reverse),
    ]
