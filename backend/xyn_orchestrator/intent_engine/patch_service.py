from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from django.db import transaction

from xyn_orchestrator.models import Artifact, ArtifactRevision, ContextPack, UserIdentity
from xyn_orchestrator.video_explainer import default_video_spec, normalize_video_scene, validate_video_spec

from .types import ARTICLE_PATCHABLE_FIELDS, CONTEXT_PACK_PATCHABLE_FIELDS

DURATION_OPTIONS = {"2m", "5m", "8m", "12m"}


class PatchValidationError(ValueError):
    pass


def _normalize_format_external(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw in {"explainer_video", "video_explainer"}:
        return "explainer_video"
    if raw in {"article", "guide", "tour", "standard"}:
        return raw if raw in {"article", "guide", "tour"} else "article"
    raise PatchValidationError("invalid format")


def to_internal_format(value: Any) -> str:
    normalized = _normalize_format_external(value)
    return "video_explainer" if normalized == "explainer_video" else "standard"


def from_internal_format(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw == "video_explainer":
        return "explainer_video"
    return "article"


def _latest_content(artifact: Artifact) -> Dict[str, Any]:
    latest = ArtifactRevision.objects.filter(artifact=artifact).order_by("-revision_number").first()
    return dict((latest.content_json if latest else {}) or {})


def _current_values(artifact: Artifact) -> Dict[str, Any]:
    content = _latest_content(artifact)
    scope = dict(artifact.scope_json or {})
    video_spec = dict(artifact.video_spec_json or {}) if isinstance(artifact.video_spec_json, dict) else {}
    return {
        "title": artifact.title,
        "category": str(scope.get("category") or ""),
        "format": from_internal_format(artifact.format),
        "intent": str(video_spec.get("intent") or ""),
        "duration": str(video_spec.get("duration") or ""),
        "scenes": list(video_spec.get("scenes") or []) if isinstance(video_spec.get("scenes"), list) else [],
        "tags": list(content.get("tags") or scope.get("tags") or []),
        "summary": str(content.get("summary") or ""),
        "body": str(content.get("body_markdown") or ""),
    }


def validate_patch(*, artifact: Artifact, patch_object: Dict[str, Any], allowed_categories: List[str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    if not isinstance(patch_object, dict):
        raise PatchValidationError("patch_object must be an object")
    unknown_fields = [key for key in patch_object.keys() if key not in ARTICLE_PATCHABLE_FIELDS]
    if unknown_fields:
        raise PatchValidationError(f"unsupported patch fields: {', '.join(sorted(unknown_fields))}")

    current = _current_values(artifact)
    normalized: Dict[str, Any] = {}
    changes: List[Dict[str, Any]] = []

    for field_name, next_value in patch_object.items():
        if field_name == "title":
            value = str(next_value or "").strip()
            if not value:
                raise PatchValidationError("title cannot be empty")
            normalized[field_name] = value
        elif field_name == "category":
            value = str(next_value or "").strip().lower()
            if not value:
                raise PatchValidationError("category cannot be empty")
            if allowed_categories and value not in set(allowed_categories):
                raise PatchValidationError("invalid category")
            normalized[field_name] = value
        elif field_name == "format":
            normalized[field_name] = _normalize_format_external(next_value)
        elif field_name == "intent":
            value = str(next_value or "").strip()
            if not value:
                raise PatchValidationError("intent cannot be empty")
            normalized[field_name] = value
        elif field_name == "duration":
            value = str(next_value or "").strip().lower()
            if value and value not in DURATION_OPTIONS:
                raise PatchValidationError("invalid duration")
            normalized[field_name] = value
        elif field_name == "scenes":
            if not isinstance(next_value, list):
                raise PatchValidationError("scenes must be a list")
            scenes = [normalize_video_scene(item, index=idx) for idx, item in enumerate(next_value, start=1) if isinstance(item, dict)]
            if scenes and len(scenes) < 3:
                raise PatchValidationError("scenes must include at least 3 items")
            normalized[field_name] = scenes
        elif field_name == "tags":
            if not isinstance(next_value, list):
                raise PatchValidationError("tags must be a list")
            normalized[field_name] = [str(v).strip() for v in next_value if str(v).strip()]
        elif field_name in {"summary", "body"}:
            normalized[field_name] = str(next_value or "")

        if current.get(field_name) != normalized.get(field_name):
            changes.append({"field": field_name, "from": current.get(field_name), "to": normalized.get(field_name)})

    return normalized, changes


def _content_hash_for_pack(pack: ContextPack) -> str:
    return hashlib.sha256(str(pack.content_markdown or "").encode("utf-8")).hexdigest()


def _normalize_context_pack_format(pack: ContextPack) -> str:
    applies = pack.applies_to_json if isinstance(pack.applies_to_json, dict) else {}
    raw = str(applies.get("content_format") or "").strip().lower()
    return raw if raw in {"json", "yaml", "text"} else "json"


def _validate_context_pack_content(format_name: str, content: str):
    normalized_format = str(format_name or "").strip().lower()
    payload = str(content or "")
    if normalized_format == "json":
        try:
            json.loads(payload or "{}")
        except Exception as exc:
            raise PatchValidationError(f"invalid json content: {exc}") from exc
        return
    if normalized_format == "yaml":
        try:
            import yaml  # type: ignore

            yaml.safe_load(payload or "")
        except Exception as exc:
            raise PatchValidationError(f"invalid yaml content: {exc}") from exc
        return
    if normalized_format != "text":
        raise PatchValidationError("invalid format")


def _context_pack_current_values(pack: ContextPack) -> Dict[str, Any]:
    applies = pack.applies_to_json if isinstance(pack.applies_to_json, dict) else {}
    tags = applies.get("tags") if isinstance(applies.get("tags"), list) else []
    return {
        "title": str(pack.name or ""),
        "summary": str(applies.get("summary") or ""),
        "tags": [str(tag).strip() for tag in tags if str(tag).strip()],
        "content": str(pack.content_markdown or ""),
        "format": _normalize_context_pack_format(pack),
    }


def validate_context_pack_patch(*, pack: ContextPack, patch_object: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    if not isinstance(patch_object, dict):
        raise PatchValidationError("patch_object must be an object")
    unknown_fields = [key for key in patch_object.keys() if key not in CONTEXT_PACK_PATCHABLE_FIELDS]
    if unknown_fields:
        raise PatchValidationError(f"unsupported patch fields: {', '.join(sorted(unknown_fields))}")

    current = _context_pack_current_values(pack)
    normalized: Dict[str, Any] = {}
    changes: List[Dict[str, Any]] = []

    for field_name, next_value in patch_object.items():
        if field_name == "title":
            value = str(next_value or "").strip()
            if not value:
                raise PatchValidationError("title cannot be empty")
            normalized[field_name] = value
        elif field_name == "summary":
            normalized[field_name] = str(next_value or "")
        elif field_name == "tags":
            if not isinstance(next_value, list):
                raise PatchValidationError("tags must be a list")
            normalized[field_name] = [str(v).strip() for v in next_value if str(v).strip()]
        elif field_name == "content":
            normalized[field_name] = str(next_value or "")
        elif field_name == "format":
            value = str(next_value or "").strip().lower()
            if value not in {"json", "yaml", "text"}:
                raise PatchValidationError("invalid format")
            normalized[field_name] = value

    effective_format = str(normalized.get("format") or current.get("format") or "json")
    if "content" in normalized or "format" in normalized:
        _validate_context_pack_content(effective_format, str(normalized.get("content") or current.get("content") or ""))

    for field_name, value in normalized.items():
        if current.get(field_name) != value:
            changes.append({"field": field_name, "from": current.get(field_name), "to": value})
    return normalized, changes


def apply_context_pack_patch(*, pack: ContextPack, actor: UserIdentity, patch_object: Dict[str, Any]) -> Tuple[ContextPack, Dict[str, str], List[Dict[str, Any]]]:
    normalized, changes = validate_context_pack_patch(pack=pack, patch_object=patch_object)
    if not changes:
        return pack, {"before_hash": _content_hash_for_pack(pack), "after_hash": _content_hash_for_pack(pack)}, changes

    before_hash = _content_hash_for_pack(pack)
    with transaction.atomic():
        dirty_fields: set[str] = set()
        applies = dict(pack.applies_to_json or {}) if isinstance(pack.applies_to_json, dict) else {}
        if "title" in normalized:
            pack.name = str(normalized["title"])
            dirty_fields.add("name")
        if "content" in normalized:
            pack.content_markdown = str(normalized["content"])
            dirty_fields.add("content_markdown")
        if "summary" in normalized:
            applies["summary"] = str(normalized["summary"])
            dirty_fields.add("applies_to_json")
        if "tags" in normalized:
            applies["tags"] = list(normalized["tags"])
            dirty_fields.add("applies_to_json")
        if "format" in normalized:
            applies["content_format"] = str(normalized["format"])
            dirty_fields.add("applies_to_json")
        if "applies_to_json" in dirty_fields:
            pack.applies_to_json = applies
        if hasattr(pack, "updated_by_id"):
            pack.updated_by = actor.user if hasattr(actor, "user") else None
            dirty_fields.add("updated_by")
        if dirty_fields:
            pack.save(update_fields=sorted(dirty_fields | {"updated_at"}))
    after_hash = _content_hash_for_pack(pack)
    return pack, {"before_hash": before_hash, "after_hash": after_hash}, changes


def apply_patch(*, artifact: Artifact, actor: UserIdentity, patch_object: Dict[str, Any], category_resolver) -> Artifact:
    allowed_categories = [str(item.get("slug") if isinstance(item, dict) else item).strip().lower() for item in (category_resolver() or [])]
    normalized, changes = validate_patch(artifact=artifact, patch_object=patch_object, allowed_categories=allowed_categories)
    if not changes:
        return artifact

    with transaction.atomic():
        dirty_fields = set()
        scope = dict(artifact.scope_json or {})

        if "title" in normalized:
            artifact.title = normalized["title"]
            dirty_fields.add("title")

        if "category" in normalized:
            scope["category"] = normalized["category"]
            dirty_fields.add("scope_json")

        if "format" in normalized:
            artifact.format = to_internal_format(normalized["format"])
            dirty_fields.add("format")

        if "intent" in normalized or "duration" in normalized or "scenes" in normalized or artifact.format == "video_explainer":
            spec = dict(artifact.video_spec_json or {}) if isinstance(artifact.video_spec_json, dict) else default_video_spec(title=artifact.title, summary="")
            if "intent" in normalized:
                spec["intent"] = normalized["intent"]
            if "duration" in normalized and normalized["duration"]:
                spec["duration"] = normalized["duration"]
            if "scenes" in normalized:
                spec["scenes"] = normalized["scenes"]
            spec_errors = validate_video_spec(spec, require_scenes=(artifact.format == "video_explainer" or str(normalized.get("format") or "") == "explainer_video"))
            if spec_errors:
                raise PatchValidationError("invalid resulting video spec")
            artifact.video_spec_json = spec
            dirty_fields.add("video_spec_json")

        content_fields = {key for key in ("summary", "body", "tags", "title") if key in normalized}
        if content_fields:
            latest = ArtifactRevision.objects.filter(artifact=artifact).order_by("-revision_number").first()
            content = deepcopy(dict((latest.content_json if latest else {}) or {}))
            if "title" in normalized:
                content["title"] = normalized["title"]
            if "summary" in normalized:
                content["summary"] = normalized["summary"]
            if "body" in normalized:
                content["body_markdown"] = normalized["body"]
            if "tags" in normalized:
                content["tags"] = normalized["tags"]
            next_revision = (latest.revision_number if latest else 0) + 1
            ArtifactRevision.objects.create(
                artifact=artifact,
                revision_number=next_revision,
                content_json=content,
                created_by=actor,
            )
            artifact.version = next_revision
            dirty_fields.add("version")

        if "scope_json" in dirty_fields:
            artifact.scope_json = scope

        if dirty_fields:
            artifact.save(update_fields=sorted(dirty_fields | {"updated_at"}))

    return artifact
