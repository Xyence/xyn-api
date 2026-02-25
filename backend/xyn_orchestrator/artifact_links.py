from __future__ import annotations

from typing import Optional

from django.db import transaction

from .models import Artifact, ArtifactType, Blueprint, BlueprintDraftSession, ContextPack, Module, UserIdentity, Workspace

DRAFT_SESSION_ARTIFACT_TYPE_SLUG = "draft_session"
BLUEPRINT_ARTIFACT_TYPE_SLUG = "blueprint"
MODULE_ARTIFACT_TYPE_SLUG = "module"
CONTEXT_PACK_ARTIFACT_TYPE_SLUG = "context_pack"


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


def _ensure_module_type() -> ArtifactType:
    artifact_type, _ = ArtifactType.objects.get_or_create(
        slug=MODULE_ARTIFACT_TYPE_SLUG,
        defaults={
            "name": "Module",
            "description": "Module artifact",
            "icon": "Box",
            "schema_json": {"entity": "Module"},
        },
    )
    return artifact_type


def _ensure_context_pack_type() -> ArtifactType:
    artifact_type, _ = ArtifactType.objects.get_or_create(
        slug=CONTEXT_PACK_ARTIFACT_TYPE_SLUG,
        defaults={
            "name": "Context Pack",
            "description": "Context pack artifact",
            "icon": "Layers",
            "schema_json": {"entity": "ContextPack"},
        },
    )
    return artifact_type


def get_current_canonical(family_id: str) -> Optional[Artifact]:
    value = str(family_id or "").strip()
    if not value:
        return None
    return (
        Artifact.objects.select_related("type")
        .filter(type__slug=BLUEPRINT_ARTIFACT_TYPE_SLUG, family_id=value, artifact_state="canonical")
        .order_by("-updated_at", "-created_at")
        .first()
    )


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
            family_id="",
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
    family_id = str(blueprint.blueprint_family_id or "").strip()
    if blueprint.artifact_id:
        artifact = blueprint.artifact
        dirty_fields = []
        if family_id and artifact.family_id != family_id:
            artifact.family_id = family_id
            dirty_fields.append("family_id")
        elif not artifact.family_id:
            artifact.family_id = str(artifact.id)
            dirty_fields.append("family_id")
        if parent_artifact and artifact.parent_artifact_id != parent_artifact.id:
            artifact.parent_artifact = parent_artifact
            artifact.lineage_root = parent_artifact.lineage_root or parent_artifact
            dirty_fields.extend(["parent_artifact", "lineage_root"])
        if dirty_fields:
            artifact.save(update_fields=list(dict.fromkeys([*dirty_fields, "updated_at"])))
        if not blueprint.blueprint_family_id:
            blueprint.blueprint_family_id = artifact.family_id
            blueprint.save(update_fields=["blueprint_family_id", "updated_at"])
        return artifact
    existing = Artifact.objects.filter(source_ref_type="Blueprint", source_ref_id=str(blueprint.id)).first()
    if existing:
        dirty_fields = []
        if family_id and existing.family_id != family_id:
            existing.family_id = family_id
            dirty_fields.append("family_id")
        elif not existing.family_id:
            existing.family_id = str(existing.id)
            dirty_fields.append("family_id")
        if parent_artifact and existing.parent_artifact_id != parent_artifact.id:
            existing.parent_artifact = parent_artifact
            existing.lineage_root = parent_artifact.lineage_root or parent_artifact
            dirty_fields.extend(["parent_artifact", "lineage_root"])
        if dirty_fields:
            existing.save(update_fields=list(dict.fromkeys([*dirty_fields, "updated_at"])))
        if not blueprint.blueprint_family_id:
            blueprint.blueprint_family_id = existing.family_id
            blueprint.save(update_fields=["blueprint_family_id", "updated_at"])
        blueprint.artifact = existing
        blueprint.save(update_fields=["artifact", "updated_at"])
        return existing

    workspace = _default_workspace()
    artifact_type = _ensure_blueprint_type()
    owner = _identity_for_user(owner_user or blueprint.created_by)
    artifact_state = "deprecated" if blueprint.status in {"archived", "deprovisioned"} else "canonical"
    artifact_status = "deprecated" if artifact_state == "deprecated" else "reviewed"
    if not family_id:
        family_id = str(blueprint.id)

    with transaction.atomic():
        artifact = Artifact.objects.create(
            workspace=workspace,
            type=artifact_type,
            artifact_state=artifact_state,
            family_id=family_id,
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
            if not artifact.family_id:
                artifact.family_id = str(artifact.id)
                artifact.save(update_fields=["lineage_root", "family_id", "updated_at"])
            else:
                artifact.save(update_fields=["lineage_root", "updated_at"])
        if not blueprint.blueprint_family_id:
            blueprint.blueprint_family_id = artifact.family_id
        blueprint.artifact = artifact
        blueprint.save(update_fields=["artifact", "blueprint_family_id", "updated_at"])
    return artifact


def ensure_module_artifact(module: Module, *, owner_user=None) -> Artifact:
    existing = Artifact.objects.filter(source_ref_type="Module", source_ref_id=str(module.id)).first()
    if existing:
        return existing
    workspace = _default_workspace()
    artifact_type = _ensure_module_type()
    owner = _identity_for_user(owner_user or module.created_by)
    artifact_state = "deprecated" if module.status in {"deprecated", "archived"} else "canonical"
    return Artifact.objects.create(
        workspace=workspace,
        type=artifact_type,
        artifact_state=artifact_state,
        title=(module.name or "Untitled module").strip() or "Untitled module",
        summary=f"{module.namespace}.{module.name}",
        schema_version="module_spec.v1",
        source_ref_type="Module",
        source_ref_id=str(module.id),
        author=owner,
        custodian=owner,
        status="published" if artifact_state == "canonical" else "deprecated",
        visibility="team",
        scope_json={"namespace": module.namespace, "fqn": module.fqn, "type": module.type},
        provenance_json={"source_system": "xyn", "source_model": "Module", "source_id": str(module.id)},
    )


def ensure_context_pack_artifact(pack: ContextPack, *, owner_user=None) -> Artifact:
    existing = Artifact.objects.filter(source_ref_type="ContextPack", source_ref_id=str(pack.id)).first()
    if existing:
        return existing
    workspace = _default_workspace()
    artifact_type = _ensure_context_pack_type()
    owner = _identity_for_user(owner_user or pack.created_by)
    artifact_state = "canonical" if pack.is_active else "deprecated"
    return Artifact.objects.create(
        workspace=workspace,
        type=artifact_type,
        artifact_state=artifact_state,
        title=(pack.name or "Untitled context pack").strip() or "Untitled context pack",
        summary=f"{pack.purpose} · {pack.scope} · v{pack.version}",
        schema_version="context_pack.v1",
        source_ref_type="ContextPack",
        source_ref_id=str(pack.id),
        author=owner,
        custodian=owner,
        status="published" if artifact_state == "canonical" else "deprecated",
        visibility="team",
        scope_json={"purpose": pack.purpose, "scope": pack.scope, "namespace": pack.namespace, "project_key": pack.project_key},
        provenance_json={"source_system": "xyn", "source_model": "ContextPack", "source_id": str(pack.id)},
    )
