import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


VIDEO_RENDER_STATUSES = {"not_started", "queued", "running", "succeeded", "failed", "canceled"}


def _scene_on_screen(value: str) -> str:
    words = [word for word in str(value or "").strip().split() if word]
    return " ".join(words[:12]).strip()


def _scene_voiceover(value: str, *, fallback: str) -> str:
    text = str(value or "").strip()
    return text or fallback


def normalize_video_scene(item: Dict[str, Any], *, index: int) -> Dict[str, Any]:
    scene_id = str(item.get("id") or f"s{index}").strip() or f"s{index}"
    title = str(item.get("title") or item.get("name") or f"Scene {index}").strip() or f"Scene {index}"
    voiceover = _scene_voiceover(
        item.get("voiceover") or item.get("narration"),
        fallback=f"{title}.",
    )
    on_screen = _scene_on_screen(item.get("on_screen") or item.get("on_screen_text") or title)
    if not on_screen:
        on_screen = f"Scene {index}"
    return {
        "id": scene_id,
        "title": title,
        "voiceover": voiceover,
        "on_screen": on_screen,
    }


def deterministic_scene_scaffold(
    *,
    title: str,
    topic: str,
    audience: str = "",
    description: str = "",
    scene_count: int = 5,
) -> List[Dict[str, Any]]:
    resolved_title = str(title or "Explainer Video").strip() or "Explainer Video"
    resolved_topic = str(topic or resolved_title).strip() or resolved_title
    resolved_audience = str(audience or "").strip()
    resolved_description = str(description or "").strip()
    count = max(3, min(int(scene_count or 5), 7))
    topic_lower = resolved_topic.lower()
    if "salamander" in topic_lower:
        biology_scenes = [
            {
                "title": "Meet the salamanders",
                "voiceover": (
                    "Salamanders are amphibians with moist skin and long tails, spanning more than 700 known species. "
                    "They bridge aquatic and terrestrial ecosystems."
                ),
                "on_screen": "Amphibians across diverse habitats",
            },
            {
                "title": "Habitat and life cycle",
                "voiceover": (
                    "Most salamanders rely on cool, damp environments such as forests, streams, and wetlands. "
                    "Many begin life as aquatic larvae before transitioning to land."
                ),
                "on_screen": "Forests, streams, wetlands",
            },
            {
                "title": "Regeneration abilities",
                "voiceover": (
                    "Some salamanders can regenerate limbs, tail tissue, and even parts of the spinal cord. "
                    "Researchers study this process to understand tissue repair."
                ),
                "on_screen": "Regeneration in action",
            },
            {
                "title": "Role in ecosystems",
                "voiceover": (
                    "Salamanders help control insect populations and serve as prey for birds and mammals. "
                    "Their abundance is often used as an indicator of ecosystem health."
                ),
                "on_screen": "Key ecosystem indicators",
            },
            {
                "title": "Conservation takeaway",
                "voiceover": (
                    "Habitat loss, pollution, and climate shifts threaten salamander populations. "
                    "Protecting wetlands and forests helps preserve their biodiversity and ecological value."
                ),
                "on_screen": "Protect habitat, protect species",
            },
        ]
        if resolved_audience:
            biology_scenes[0]["voiceover"] = f"{biology_scenes[0]['voiceover']} This overview is tailored for {resolved_audience}."
        selected = biology_scenes[:count]
        return [normalize_video_scene({"id": f"s{idx + 1}", **row}, index=idx + 1) for idx, row in enumerate(selected)]

    plans = [
        (f"{resolved_topic.title()}: core premise", "Topic overview"),
        (f"{resolved_topic.title()}: context", "Context"),
        (f"{resolved_topic.title()}: key points", "Key points"),
        (f"{resolved_topic.title()}: takeaways", "Takeaways"),
        (f"{resolved_topic.title()}: closing", "Closing"),
    ]
    if count <= 3:
        plans = [
            (f"{resolved_topic.title()}: premise", "Premise"),
            (f"{resolved_topic.title()}: core points", "Core points"),
            (f"{resolved_topic.title()}: takeaway", "Takeaway"),
        ]
    scenes: List[Dict[str, Any]] = []
    for idx in range(count):
        plan = plans[idx] if idx < len(plans) else (f"{resolved_topic.title()}: detail {idx - len(plans) + 1}", "Additional detail")
        if idx == 0:
            voice = f"{resolved_topic.title()} is the central focus of this explainer."
        elif idx == count - 1:
            voice = f"The closing takeaway is why {resolved_topic.lower()} matters in practice."
        else:
            detail = resolved_description or f"This section covers practical context and evidence related to {resolved_topic.lower()}."
            voice = detail
        if resolved_audience and idx in {0, 1}:
            voice = f"{voice} The explanation is tuned for {resolved_audience}."
        scenes.append(
            normalize_video_scene(
                {
                    "id": f"s{idx + 1}",
                    "title": plan[0],
                    "voiceover": voice,
                    "on_screen": plan[1],
                },
                index=idx + 1,
            )
        )
    return scenes


def default_video_spec(title: str = "", summary: str = "", *, scenes: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
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
        "scenes": list(scenes or []),
        "generation": {
            "provider": None,
            "status": "not_started",
            "last_render_id": None,
            "updated_at": now,
        },
    }


def validate_video_spec(spec: Dict[str, Any], *, require_scenes: bool = False) -> List[str]:
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
    elif require_scenes and len(scenes) < 3:
        errors.append("scenes must include at least 3 items for explainer_video")
    elif scenes:
        for idx, scene in enumerate(scenes, start=1):
            if not isinstance(scene, dict):
                errors.append(f"scenes[{idx - 1}] must be an object")
                continue
            normalized = normalize_video_scene(scene, index=idx)
            if not normalized.get("id"):
                errors.append(f"scenes[{idx - 1}].id is required")
            if not normalized.get("title"):
                errors.append(f"scenes[{idx - 1}].title is required")
            if not normalized.get("voiceover"):
                errors.append(f"scenes[{idx - 1}].voiceover is required")
            if not normalized.get("on_screen"):
                errors.append(f"scenes[{idx - 1}].on_screen is required")
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


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


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
    payload = {
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
    return _json_safe(payload)


def export_package_text(article_payload: Dict[str, Any], latest_render_payload: Dict[str, Any] | None = None) -> str:
    return json.dumps(export_package_payload(article_payload, latest_render_payload), indent=2, sort_keys=True)
