from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from django.db import IntegrityError

from .models import Artifact, Blueprint, BlueprintDraftSession, LedgerEvent, UserIdentity

MEANINGFUL_ARTIFACT_FIELDS = (
    "title",
    "summary",
    "tags_json",
    "artifact_state",
    "schema_version",
    "parent_artifact_id",
    "lineage_root_id",
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _small_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        if len(value) > 280:
            return {"preview": value[:200], "hash": hashlib.sha256(value.encode("utf-8")).hexdigest()}
        return value
    if isinstance(value, (int, float, bool)):
        return value
    return {"hash": hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()}


def _source_snapshot(source: Any) -> Dict[str, Any]:
    if isinstance(source, Blueprint):
        return {
            "title": source.name or "",
            "namespace": source.namespace or "",
            "description_hash": hashlib.sha256((source.description or "").encode("utf-8")).hexdigest(),
            "spec_hash": hashlib.sha256((source.spec_text or "").encode("utf-8")).hexdigest(),
        }
    if isinstance(source, BlueprintDraftSession):
        return {
            "title": source.title or source.name or "",
            "draft_kind": source.draft_kind or "",
            "blueprint_kind": source.blueprint_kind or "",
            "namespace": source.namespace or "",
            "project_key": source.project_key or "",
            "draft_hash": hashlib.sha256(_canonical_json(source.current_draft_json or {}).encode("utf-8")).hexdigest(),
        }
    return {}


def compute_artifact_diff(
    old_artifact: Artifact,
    new_artifact: Artifact,
    *,
    old_source: Any = None,
    new_source: Any = None,
) -> Dict[str, Any]:
    changed_fields = []
    diff: Dict[str, Dict[str, Any]] = {}

    for field in MEANINGFUL_ARTIFACT_FIELDS:
        old_value = getattr(old_artifact, field)
        new_value = getattr(new_artifact, field)
        if old_value != new_value:
            changed_fields.append(field)
            diff[field] = {"from": _small_value(old_value), "to": _small_value(new_value)}

    old_source_snap = _source_snapshot(old_source)
    new_source_snap = _source_snapshot(new_source)
    for key in sorted(set(old_source_snap.keys()) | set(new_source_snap.keys())):
        if old_source_snap.get(key) != new_source_snap.get(key):
            field = f"source.{key}"
            changed_fields.append(field)
            diff[field] = {"from": _small_value(old_source_snap.get(key)), "to": _small_value(new_source_snap.get(key))}

    return {"changed_fields": changed_fields, "diff": diff}


def make_dedupe_key(
    action: str,
    artifact_id: str,
    *,
    diff_payload: Optional[Dict[str, Any]] = None,
    target_artifact_id: Optional[str] = None,
    state: Optional[str] = None,
) -> str:
    if action == "artifact.create":
        return f"artifact.create:{artifact_id}"
    if action == "artifact.canonize":
        return f"artifact.canonize:{artifact_id}:{target_artifact_id or ''}"
    if action in {"artifact.deprecate", "artifact.archive"}:
        return f"artifact.state:{artifact_id}:{state or action}"
    if action == "artifact.update":
        digest = hashlib.sha256(_canonical_json(diff_payload or {}).encode("utf-8")).hexdigest()
        return f"artifact.update:{artifact_id}:{digest}"
    return f"{action}:{artifact_id}"


def _system_identity() -> UserIdentity:
    identity = UserIdentity.objects.filter(provider="system", subject="xyn-system").first()
    if identity:
        return identity
    return UserIdentity.objects.create(
        provider="system",
        issuer="xyn://system",
        subject="xyn-system",
        email="system@xyn.local",
        display_name="Xyn System",
    )


def emit_ledger_event(
    *,
    actor: Optional[UserIdentity],
    action: str,
    artifact: Artifact,
    summary: str,
    metadata: Optional[Dict[str, Any]] = None,
    dedupe_key: str = "",
) -> Optional[LedgerEvent]:
    if dedupe_key and LedgerEvent.objects.filter(dedupe_key=dedupe_key).exists():
        return None
    try:
        return LedgerEvent.objects.create(
            actor_user=actor or _system_identity(),
            action=action,
            artifact=artifact,
            artifact_type=artifact.type.slug if artifact.type_id else "",
            artifact_state=artifact.artifact_state or "",
            parent_artifact=artifact.parent_artifact,
            lineage_root=artifact.lineage_root,
            summary=summary[:280],
            metadata_json=metadata or {},
            dedupe_key=dedupe_key or "",
            source_ref_type=artifact.source_ref_type or "",
            source_ref_id=artifact.source_ref_id or "",
        )
    except IntegrityError:
        return None
