from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

from django.db import transaction

from xyn_orchestrator.models import Artifact, ArtifactRevision, UserIdentity
from xyn_orchestrator.video_explainer import default_video_spec, validate_video_spec

from .types import PATCHABLE_FIELDS

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
        "tags": list(content.get("tags") or scope.get("tags") or []),
        "summary": str(content.get("summary") or ""),
        "body": str(content.get("body_markdown") or ""),
    }


def validate_patch(*, artifact: Artifact, patch_object: Dict[str, Any], allowed_categories: List[str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    if not isinstance(patch_object, dict):
        raise PatchValidationError("patch_object must be an object")
    unknown_fields = [key for key in patch_object.keys() if key not in PATCHABLE_FIELDS]
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
        elif field_name == "tags":
            if not isinstance(next_value, list):
                raise PatchValidationError("tags must be a list")
            normalized[field_name] = [str(v).strip() for v in next_value if str(v).strip()]
        elif field_name in {"summary", "body"}:
            normalized[field_name] = str(next_value or "")

        if current.get(field_name) != normalized.get(field_name):
            changes.append({"field": field_name, "from": current.get(field_name), "to": normalized.get(field_name)})

    return normalized, changes


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

        if "intent" in normalized or "duration" in normalized or artifact.format == "video_explainer":
            spec = dict(artifact.video_spec_json or {}) if isinstance(artifact.video_spec_json, dict) else default_video_spec(title=artifact.title, summary="")
            if "intent" in normalized:
                spec["intent"] = normalized["intent"]
            if "duration" in normalized and normalized["duration"]:
                spec["duration"] = normalized["duration"]
            spec_errors = validate_video_spec(spec)
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
