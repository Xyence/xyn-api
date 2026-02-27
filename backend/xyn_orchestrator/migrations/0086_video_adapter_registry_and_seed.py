import hashlib
import json
import uuid

from django.db import migrations


SEEDED_ADAPTER_CONFIG = {
    "adapter_id": "google_veo",
    "provider_model_id": "veo-3.1",
    "credential_ref": "gcp-veo-prod",
    "render_caps": {"max_duration_s": 12, "max_resolution": "1920x1080", "fps_options": [24, 30]},
    "defaults": {"fps": 24, "resolution": "1280x720", "aspect_ratio": "16:9"},
}


def seed_video_adapter_config(apps, schema_editor):
    Workspace = apps.get_model("xyn_orchestrator", "Workspace")
    ArtifactType = apps.get_model("xyn_orchestrator", "ArtifactType")
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")
    ArtifactRevision = apps.get_model("xyn_orchestrator", "ArtifactRevision")

    workspace, _ = Workspace.objects.get_or_create(
        slug="platform-builder",
        defaults={"name": "Platform Builder", "description": "Platform governance and operator documentation"},
    )
    adapter_type, _ = ArtifactType.objects.get_or_create(
        slug="video_adapter_config",
        defaults={
            "name": "Video Adapter Config",
            "description": "Governed configuration for video renderer adapters",
            "icon": "Settings2",
            "schema_json": {"version": 1},
        },
    )
    ArtifactType.objects.get_or_create(
        slug="render_package",
        defaults={
            "name": "Render Package",
            "description": "Versioned render package snapshot produced from explainer artifacts",
            "icon": "Package",
            "schema_json": {"version": 1},
        },
    )

    existing = Artifact.objects.filter(type=adapter_type, slug="google-veo-prod").first()
    if existing:
        return

    artifact = Artifact.objects.create(
        id=uuid.uuid4(),
        workspace=workspace,
        type=adapter_type,
        artifact_state="canonical",
        title="Google Veo Production",
        slug="google-veo-prod",
        summary="Seeded Google Veo adapter configuration.",
        schema_version="video_adapter_config.v1",
        status="published",
        version=1,
        visibility="team",
        source_ref_type="VideoAdapterConfig",
        source_ref_id="",
        scope_json={"adapter_id": "google_veo"},
        provenance_json={"source_system": "seed", "seed_slug": "google-veo-prod"},
    )
    artifact.lineage_root = artifact
    artifact.save(update_fields=["lineage_root", "updated_at"])
    ArtifactRevision.objects.create(
        artifact=artifact,
        revision_number=1,
        content_json=dict(SEEDED_ADAPTER_CONFIG),
        created_by=None,
    )
    normalized = json.dumps(SEEDED_ADAPTER_CONFIG, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    artifact.content_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    artifact.validation_status = "pass"
    artifact.validation_errors_json = []
    artifact.save(update_fields=["content_hash", "validation_status", "validation_errors_json", "updated_at"])


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0085_intent_scripts_and_golden_path_tours"),
    ]

    operations = [
        migrations.RunPython(seed_video_adapter_config, migrations.RunPython.noop),
    ]
