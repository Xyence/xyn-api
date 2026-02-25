from django.db import migrations, models
import django.db.models.deletion
from django.db.models import Q


def _default_workspace(Workspace):
    workspace = Workspace.objects.filter(slug="platform-builder").first()
    if workspace:
        return workspace
    return Workspace.objects.create(
        slug="platform-builder",
        name="Platform Builder",
        description="Platform Builder workspace",
    )


def _identity_for_user(UserIdentity, user):
    if not user:
        return None
    email = str(getattr(user, "email", "") or "").strip()
    if not email:
        return None
    return UserIdentity.objects.filter(email__iexact=email).order_by("-updated_at").first()


def forward(apps, schema_editor):
    Workspace = apps.get_model("xyn_orchestrator", "Workspace")
    ArtifactType = apps.get_model("xyn_orchestrator", "ArtifactType")
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")
    Blueprint = apps.get_model("xyn_orchestrator", "Blueprint")
    BlueprintDraftSession = apps.get_model("xyn_orchestrator", "BlueprintDraftSession")
    UserIdentity = apps.get_model("xyn_orchestrator", "UserIdentity")

    workspace = _default_workspace(Workspace)

    draft_session_type, _ = ArtifactType.objects.get_or_create(
        slug="draft_session",
        defaults={
            "name": "Draft Session",
            "description": "Draft session artifact",
            "icon": "FilePenLine",
            "schema_json": {"entity": "BlueprintDraftSession"},
        },
    )
    blueprint_type, _ = ArtifactType.objects.get_or_create(
        slug="blueprint",
        defaults={
            "name": "Blueprint",
            "description": "Blueprint artifact",
            "icon": "LayoutTemplate",
            "schema_json": {"entity": "Blueprint"},
        },
    )

    for session in BlueprintDraftSession.objects.all().order_by("created_at"):
        if session.artifact_id:
            continue
        artifact = Artifact.objects.filter(
            source_ref_type="BlueprintDraftSession",
            source_ref_id=str(session.id),
        ).first()
        if not artifact:
            title = (session.title or session.name or "Untitled draft").strip() or "Untitled draft"
            owner = _identity_for_user(UserIdentity, getattr(session, "created_by", None))
            artifact = Artifact.objects.create(
                workspace=workspace,
                type=draft_session_type,
                artifact_state="provisional",
                title=title,
                summary="",
                schema_version="v1",
                tags_json=[],
                status="draft",
                version=1,
                visibility="private",
                author=owner,
                custodian=owner,
                source_ref_type="BlueprintDraftSession",
                source_ref_id=str(session.id),
                scope_json={
                    "kind": session.draft_kind,
                    "namespace": session.namespace or "",
                    "project_key": session.project_key or "",
                },
                provenance_json={"source_system": "xyn", "source_model": "BlueprintDraftSession", "source_id": str(session.id)},
            )
            artifact.lineage_root_id = artifact.id
            artifact.save(update_fields=["lineage_root", "updated_at"])
        session.artifact_id = artifact.id
        session.save(update_fields=["artifact", "updated_at"])

    for blueprint in Blueprint.objects.all().order_by("created_at"):
        if blueprint.artifact_id:
            continue
        artifact = Artifact.objects.filter(
            source_ref_type="Blueprint",
            source_ref_id=str(blueprint.id),
        ).first()
        if not artifact:
            owner = _identity_for_user(UserIdentity, getattr(blueprint, "created_by", None))
            artifact_state = "deprecated" if blueprint.status in {"archived", "deprovisioned"} else "canonical"
            artifact_status = "deprecated" if artifact_state == "deprecated" else "reviewed"
            artifact = Artifact.objects.create(
                workspace=workspace,
                type=blueprint_type,
                artifact_state=artifact_state,
                title=(blueprint.name or "Untitled blueprint").strip() or "Untitled blueprint",
                summary=blueprint.description or "",
                schema_version="v1",
                tags_json=[],
                status=artifact_status,
                version=1,
                visibility="team",
                author=owner,
                custodian=owner,
                source_ref_type="Blueprint",
                source_ref_id=str(blueprint.id),
                scope_json={"namespace": blueprint.namespace, "name": blueprint.name, "fqn": f"{blueprint.namespace}.{blueprint.name}"},
                provenance_json={"source_system": "xyn", "source_model": "Blueprint", "source_id": str(blueprint.id)},
            )
            artifact.lineage_root_id = artifact.id
            artifact.save(update_fields=["lineage_root", "updated_at"])
        blueprint.artifact_id = artifact.id
        blueprint.save(update_fields=["artifact", "updated_at"])


def backward(apps, schema_editor):
    Blueprint = apps.get_model("xyn_orchestrator", "Blueprint")
    BlueprintDraftSession = apps.get_model("xyn_orchestrator", "BlueprintDraftSession")
    Blueprint.objects.update(artifact=None)
    BlueprintDraftSession.objects.update(artifact=None)


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0080_seed_default_tour_workflow"),
    ]

    operations = [
        migrations.AddField(
            model_name="artifact",
            name="artifact_state",
            field=models.CharField(
                choices=[
                    ("provisional", "Provisional"),
                    ("canonical", "Canonical"),
                    ("immutable", "Immutable"),
                    ("deprecated", "Deprecated"),
                ],
                default="provisional",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="artifact",
            name="lineage_root",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="lineage_descendants", to="xyn_orchestrator.artifact"),
        ),
        migrations.AddField(
            model_name="artifact",
            name="parent_artifact",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="derived_artifacts", to="xyn_orchestrator.artifact"),
        ),
        migrations.AddField(
            model_name="artifact",
            name="schema_version",
            field=models.CharField(blank=True, default="", max_length=80),
        ),
        migrations.AddField(
            model_name="artifact",
            name="source_ref_id",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.AddField(
            model_name="artifact",
            name="source_ref_type",
            field=models.CharField(blank=True, default="", max_length=80),
        ),
        migrations.AddField(
            model_name="artifact",
            name="summary",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="artifact",
            name="tags_json",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="blueprint",
            name="artifact",
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="source_blueprint", to="xyn_orchestrator.artifact"),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="artifact",
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="source_draft_session", to="xyn_orchestrator.artifact"),
        ),
        migrations.AddConstraint(
            model_name="artifact",
            constraint=models.UniqueConstraint(
                condition=(~Q(source_ref_type="") & ~Q(source_ref_id="")),
                fields=("source_ref_type", "source_ref_id"),
                name="uniq_artifact_source_ref",
            ),
        ),
        migrations.RunPython(forward, backward),
    ]
