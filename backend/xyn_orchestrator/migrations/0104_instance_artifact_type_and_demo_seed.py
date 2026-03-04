from django.db import migrations


INSTANCE_SCHEMA = {
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


def seed_instance_type_and_demo_artifact(apps, schema_editor):
    ArtifactType = apps.get_model("xyn_orchestrator", "ArtifactType")
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")
    ArtifactRevision = apps.get_model("xyn_orchestrator", "ArtifactRevision")
    Workspace = apps.get_model("xyn_orchestrator", "Workspace")

    instance_type, _ = ArtifactType.objects.get_or_create(
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

    workspace = Workspace.objects.filter(slug="platform-builder").order_by("created_at").first()
    if workspace is None:
        workspace = Workspace.objects.order_by("created_at").first()
    if workspace is None:
        workspace = Workspace.objects.create(slug="default-workspace", name="Default Workspace")

    artifact = (
        Artifact.objects.filter(type=instance_type, slug="xyn-ec2-demo")
        .order_by("-updated_at", "-created_at")
        .first()
    )
    if artifact is None:
        artifact = Artifact.objects.create(
            workspace=workspace,
            type=instance_type,
            title="xyn-ec2-demo",
            slug="xyn-ec2-demo",
            summary="Demo EC2 instance descriptor",
            schema_version="xyn.instance.v1",
            status="published",
            visibility="team",
            scope_json={"slug": "xyn-ec2-demo", "summary": "Demo EC2 instance descriptor"},
            provenance_json={"source_system": "migration", "source_id": "xyn-ec2-demo"},
        )
        ArtifactRevision.objects.create(
            artifact=artifact,
            revision_number=1,
            content_json=INSTANCE_SCHEMA,
        )
    else:
        changed = []
        if str(artifact.schema_version or "") != "xyn.instance.v1":
            artifact.schema_version = "xyn.instance.v1"
            changed.append("schema_version")
        if str(artifact.status or "") != "published":
            artifact.status = "published"
            changed.append("status")
        if changed:
            changed.append("updated_at")
            artifact.save(update_fields=changed)
        latest = (
            ArtifactRevision.objects.filter(artifact=artifact).order_by("-revision_number").first()
        )
        content = (latest.content_json if latest and isinstance(latest.content_json, dict) else {}) if latest else {}
        if content.get("schema_version") != "xyn.instance.v1":
            next_revision = int(getattr(latest, "revision_number", 0) or 0) + 1
            ArtifactRevision.objects.create(
                artifact=artifact,
                revision_number=next_revision,
                content_json=INSTANCE_SCHEMA,
            )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0103_seed_runtime_contract_artifacts"),
    ]

    operations = [
        migrations.RunPython(seed_instance_type_and_demo_artifact, noop_reverse),
    ]
