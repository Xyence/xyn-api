from __future__ import annotations

from typing import Optional

from django.db import transaction

from .models import Artifact, ArtifactType, Blueprint, BlueprintDraftSession, UserIdentity, Workspace

DRAFT_SESSION_ARTIFACT_TYPE_SLUG = "draft_session"
BLUEPRINT_ARTIFACT_TYPE_SLUG = "blueprint"


def _default_workspace() -> Workspace:
    workspace = Workspace.objects.filter(slug="platform-builder").first()
    if workspace:
        return workspace
    workspace, _ = Workspace.objects.get_or_create(
        slug="platform-builder",
        defaults={"name": "Platform Builder", "description": "Platform builder workspace"},
    )
    return workspace


def _identity_for_user(user) -> Optional[UserIdentity]:
    if not user:
        return None
    email = str(getattr(user, "email", "") or "").strip()
    if not email:
        return None
    return UserIdentity.objects.filter(email__iexact=email).order_by("-updated_at").first()


def _ensure_draft_session_type() -> ArtifactType:
    artifact_type, _ = ArtifactType.objects.get_or_create(
        slug=DRAFT_SESSION_ARTIFACT_TYPE_SLUG,
        defaults={
            "name": "Draft Session",
            "description": "Draft session artifact",
            "icon": "FilePenLine",
            "schema_json": {"entity": "BlueprintDraftSession"},
        },
    )
    return artifact_type


def _ensure_blueprint_type() -> ArtifactType:
    artifact_type, _ = ArtifactType.objects.get_or_create(
        slug=BLUEPRINT_ARTIFACT_TYPE_SLUG,
        defaults={
            "name": "Blueprint",
            "description": "Blueprint artifact",
            "icon": "LayoutTemplate",
            "schema_json": {"entity": "Blueprint"},
        },
    )
    return artifact_type


def ensure_draft_session_artifact(session: BlueprintDraftSession, *, owner_user=None) -> Artifact:
    if session.artifact_id:
        return session.artifact
    existing = Artifact.objects.filter(source_ref_type="BlueprintDraftSession", source_ref_id=str(session.id)).first()
    if existing:
        session.artifact = existing
        session.save(update_fields=["artifact", "updated_at"])
        return existing

    workspace = _default_workspace()
    artifact_type = _ensure_draft_session_type()
    owner = _identity_for_user(owner_user or session.created_by)
    title = (session.title or session.name or "Untitled draft").strip() or "Untitled draft"

    with transaction.atomic():
        artifact = Artifact.objects.create(
            workspace=workspace,
            type=artifact_type,
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
        artifact.lineage_root = artifact
        artifact.save(update_fields=["lineage_root", "updated_at"])
        session.artifact = artifact
        session.save(update_fields=["artifact", "updated_at"])
    return artifact


def ensure_blueprint_artifact(
    blueprint: Blueprint,
    *,
    owner_user=None,
    parent_artifact: Optional[Artifact] = None,
) -> Artifact:
    if blueprint.artifact_id:
        artifact = blueprint.artifact
        if parent_artifact and artifact.parent_artifact_id != parent_artifact.id:
            artifact.parent_artifact = parent_artifact
            artifact.lineage_root = parent_artifact.lineage_root or parent_artifact
            artifact.save(update_fields=["parent_artifact", "lineage_root", "updated_at"])
        return artifact
    existing = Artifact.objects.filter(source_ref_type="Blueprint", source_ref_id=str(blueprint.id)).first()
    if existing:
        if parent_artifact and existing.parent_artifact_id != parent_artifact.id:
            existing.parent_artifact = parent_artifact
            existing.lineage_root = parent_artifact.lineage_root or parent_artifact
            existing.save(update_fields=["parent_artifact", "lineage_root", "updated_at"])
        blueprint.artifact = existing
        blueprint.save(update_fields=["artifact", "updated_at"])
        return existing

    workspace = _default_workspace()
    artifact_type = _ensure_blueprint_type()
    owner = _identity_for_user(owner_user or blueprint.created_by)
    artifact_state = "deprecated" if blueprint.status in {"archived", "deprovisioned"} else "canonical"
    artifact_status = "deprecated" if artifact_state == "deprecated" else "reviewed"

    with transaction.atomic():
        artifact = Artifact.objects.create(
            workspace=workspace,
            type=artifact_type,
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
            parent_artifact=parent_artifact,
            lineage_root=(parent_artifact.lineage_root or parent_artifact) if parent_artifact else None,
            scope_json={"namespace": blueprint.namespace, "name": blueprint.name, "fqn": f"{blueprint.namespace}.{blueprint.name}"},
            provenance_json={"source_system": "xyn", "source_model": "Blueprint", "source_id": str(blueprint.id)},
        )
        if not artifact.lineage_root_id:
            artifact.lineage_root = artifact
            artifact.save(update_fields=["lineage_root", "updated_at"])
        blueprint.artifact = artifact
        blueprint.save(update_fields=["artifact", "updated_at"])
    return artifact
