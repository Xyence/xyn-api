import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


VIDEO_RENDER_STATUSES = {"not_started", "queued", "running", "succeeded", "failed", "canceled"}


def default_video_spec(title: str = "", summary: str = "") -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "version": 1,
        "title": title or "",
        "intent": summary or "",
        "audience": "mixed",
        "tone": "clear, confident, warm",
        "duration_seconds_target": 150,
        "voice": {
            "style": "conversational",
            "speaker": "neutral",
            "pace": "medium",
        },
        "script": {
            "draft": "",
            "last_generated_at": None,
            "notes": "",
            "proposals": [],
        },
        "storyboard": {
            "draft": [],
            "last_generated_at": None,
            "notes": "",
            "proposals": [],
        },
        "scenes": [],
        "generation": {
            "provider": None,
            "status": "not_started",
            "last_render_id": None,
            "updated_at": now,
        },
    }


def validate_video_spec(spec: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if not isinstance(spec, dict):
        return ["video_spec_json must be an object"]
    if not isinstance(spec.get("version"), int):
        errors.append("version must be an integer")
    if not isinstance(spec.get("title", ""), str):
        errors.append("title must be a string")
    if not isinstance(spec.get("intent", ""), str):
        errors.append("intent must be a string")
    if not isinstance(spec.get("audience", ""), str):
        errors.append("audience must be a string")
    if not isinstance(spec.get("tone", ""), str):
        errors.append("tone must be a string")
    if not isinstance(spec.get("duration_seconds_target"), int):
        errors.append("duration_seconds_target must be an integer")
    voice = spec.get("voice")
    if not isinstance(voice, dict):
        errors.append("voice must be an object")
    script = spec.get("script")
    if not isinstance(script, dict):
        errors.append("script must be an object")
    elif not isinstance(script.get("draft", ""), str):
        errors.append("script.draft must be a string")
    storyboard = spec.get("storyboard")
    if not isinstance(storyboard, dict):
        errors.append("storyboard must be an object")
    else:
        draft = storyboard.get("draft", [])
        if not isinstance(draft, list):
            errors.append("storyboard.draft must be a list")
    scenes = spec.get("scenes", [])
    if not isinstance(scenes, list):
        errors.append("scenes must be a list")
    generation = spec.get("generation", {})
    if not isinstance(generation, dict):
        errors.append("generation must be an object")
    else:
        status = str(generation.get("status") or "not_started")
        if status not in VIDEO_RENDER_STATUSES:
            errors.append("generation.status is invalid")
    return errors


def sanitize_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        result: Dict[str, Any] = {}
        for key, value in payload.items():
            lower = str(key).lower()
            if any(token in lower for token in ("key", "token", "secret", "password", "credential")):
                result[key] = "***"
            else:
                result[key] = sanitize_payload(value)
        return result
    if isinstance(payload, list):
        return [sanitize_payload(item) for item in payload]
    return payload


def _build_export_asset(article_id: str, spec: Dict[str, Any]) -> Dict[str, Any]:
    scenes = spec.get("scenes", [])
    return {
        "type": "export_package",
        "url": f"/xyn/api/articles/{article_id}/video/export-package",
        "metadata": {
            "format": "json",
            "scene_count": len(scenes) if isinstance(scenes, list) else 0,
        },
    }


def render_video(spec: Dict[str, Any], request_payload: Dict[str, Any], article_id: str) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    provider = str(request_payload.get("provider") or os.environ.get("XYENCE_VIDEO_PROVIDER") or "unknown").strip().lower() or "unknown"
    sanitized_payload = sanitize_payload(request_payload)
    if provider in {"", "unknown", "stub", "none"}:
        assets = [_build_export_asset(article_id, spec)]
        return "unknown", assets, {
            "message": "Video provider is not configured. Generated export package placeholder.",
            "provider_configured": False,
            "request": sanitized_payload,
        }

    assets = [_build_export_asset(article_id, spec)]
    return provider, assets, {
        "message": "Provider abstraction in place. Using stub render output until provider adapter is implemented.",
        "provider_configured": True,
        "provider": provider,
        "request": sanitized_payload,
    }


def export_package_payload(article_payload: Dict[str, Any], latest_render_payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
    spec = article_payload.get("video_spec_json") if isinstance(article_payload.get("video_spec_json"), dict) else {}
    return {
        "article_id": article_payload.get("id"),
        "title": article_payload.get("title"),
        "slug": article_payload.get("slug"),
        "format": article_payload.get("format"),
        "version": article_payload.get("version"),
        "video_spec_json": spec,
        "script_draft": ((spec.get("script") or {}).get("draft") if isinstance(spec.get("script"), dict) else "") or "",
        "storyboard_draft": ((spec.get("storyboard") or {}).get("draft") if isinstance(spec.get("storyboard"), dict) else []) or [],
        "scenes": spec.get("scenes") if isinstance(spec.get("scenes"), list) else [],
        "latest_render": latest_render_payload or {},
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }


def export_package_text(article_payload: Dict[str, Any], latest_render_payload: Dict[str, Any] | None = None) -> str:
    return json.dumps(export_package_payload(article_payload, latest_render_payload), indent=2, sort_keys=True)

