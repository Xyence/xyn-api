import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests


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
            # credential_ref is an identifier, not a secret value. Keep it intact so workers can resolve it later.
            if lower in {"credential_ref", "secret_ref", "model_config_id", "adapter_config_id"}:
                result[key] = sanitize_payload(value)
                continue
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


def _normalize_assets(raw_assets: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw_assets, list):
        return []
    normalized: List[Dict[str, Any]] = []
    for asset in raw_assets:
        if not isinstance(asset, dict):
            continue
        asset_type = str(asset.get("type") or "").strip() or "video"
        url = str(asset.get("url") or "").strip()
        if not url:
            continue
        normalized.append(
            {
                "type": asset_type,
                "url": url,
                "metadata": asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {},
            }
        )
    return normalized


def _render_via_http_provider(
    *,
    endpoint_url: str,
    timeout_seconds: int,
    provider_name: str,
    spec: Dict[str, Any],
    request_payload: Dict[str, Any],
    article_id: str,
) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    payload = {
        "article_id": article_id,
        "spec": spec,
        "request": sanitize_payload(request_payload),
    }
    response = requests.post(
        endpoint_url,
        json=payload,
        timeout=max(5, min(timeout_seconds, 600)),
    )
    response.raise_for_status()
    body = response.json() if response.content else {}
    assets = _normalize_assets((body or {}).get("assets"))
    if not assets:
        video_url = str((body or {}).get("video_url") or "").strip()
        if video_url:
            assets = [{"type": "video", "url": video_url, "metadata": {}}]
    if not assets:
        assets = [_build_export_asset(article_id, spec)]
    result_payload = {
        "message": "Video render request sent to external provider.",
        "provider_configured": True,
        "provider": provider_name,
        "provider_response": sanitize_payload(body),
    }
    return provider_name, assets, result_payload


def _extract_google_api_key(secret_value: str) -> str:
    value = str(secret_value or "").strip()
    if not value:
        return ""
    if value.startswith("AIza"):
        return value
    try:
        parsed = json.loads(value)
    except Exception:
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("api_key", "apiKey", "key"):
        candidate = str(parsed.get(key) or "").strip()
        if candidate.startswith("AIza"):
            return candidate
    return ""


def _resolve_secret_ref_value_lazy(ref_text: str) -> Optional[str]:
    value = str(ref_text or "").strip()
    if not value:
        return None
    internal_base_url = str(os.environ.get("XYENCE_INTERNAL_BASE_URL") or "").strip().rstrip("/")
    internal_token = str(os.environ.get("XYENCE_INTERNAL_TOKEN") or "").strip()
    if not internal_base_url or not internal_token:
        return None
    try:
        response = requests.get(
            f"{internal_base_url}/xyn/internal/secrets/resolve",
            headers={"X-Internal-Token": internal_token},
            params={"ref": value},
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json() if response.content else {}
    except Exception:
        return None
    resolved_value = str((payload or {}).get("value") or "").strip()
    return resolved_value or None


def _build_google_veo_prompt(spec: Dict[str, Any]) -> str:
    title = str(spec.get("title") or "").strip()
    intent = str(spec.get("intent") or "").strip()
    audience = str(spec.get("audience") or "").strip()
    tone = str(spec.get("tone") or "").strip()
    script_text = str(((spec.get("script") or {}).get("draft")) or "").strip() if isinstance(spec.get("script"), dict) else ""
    scenes = spec.get("scenes") if isinstance(spec.get("scenes"), list) else []
    scene_lines: List[str] = []
    for item in scenes[:8]:
        if not isinstance(item, dict):
            continue
        scene = normalize_video_scene(item, index=len(scene_lines) + 1)
        scene_lines.append(f"{scene['title']}: {scene['voiceover']} (On screen: {scene['on_screen']})")
    parts = [
        f"Create a short explainer video.",
        f"Title: {title}" if title else "",
        f"Intent: {intent}" if intent else "",
        f"Audience: {audience}" if audience else "",
        f"Tone: {tone}" if tone else "",
        f"Narration script: {script_text}" if script_text else "",
        "Scenes:\n" + "\n".join(f"- {line}" for line in scene_lines) if scene_lines else "",
        "Output should be coherent, cinematic, and aligned with this storyboard.",
    ]
    return "\n".join(part for part in parts if part).strip()


def _normalize_google_operations_url(base_url: str, operation_name: str) -> str:
    op = str(operation_name or "").strip()
    if not op:
        return ""
    if op.startswith("http://") or op.startswith("https://"):
        return op
    base = str(base_url or "https://generativelanguage.googleapis.com/v1beta").rstrip("/")
    return f"{base}/{op.lstrip('/')}"


def _extract_video_urls(payload: Any) -> List[str]:
    urls: List[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_l = str(key).lower()
            if isinstance(value, str):
                candidate = value.strip()
                if (key_l.endswith("uri") or "video" in key_l or key_l.endswith("url")) and (
                    candidate.startswith("http://")
                    or candidate.startswith("https://")
                    or candidate.startswith("gs://")
                ):
                    urls.append(candidate)
            else:
                urls.extend(_extract_video_urls(value))
    elif isinstance(payload, list):
        for item in payload:
            urls.extend(_extract_video_urls(item))
    return urls


def _google_veo_request_variants(model_id: str, prompt: str, base_url: str) -> List[Tuple[str, Dict[str, Any]]]:
    model = str(model_id or "").strip() or "veo-3.1-generate-preview"
    base = str(base_url or "https://generativelanguage.googleapis.com/v1beta").rstrip("/")
    if "/models/" in base and ":" in base:
        generate_url = base
    else:
        generate_url = f"{base}/models/{model}:generateVideos"
    predict_url = f"{base}/models/{model}:predictLongRunning"
    return [
        (
            generate_url,
            {
                "prompt": {"text": prompt},
            },
        ),
        (
            predict_url,
            {
                "instances": [{"prompt": prompt}],
                "parameters": {},
            },
        ),
    ]


def _render_via_google_veo(
    *,
    provider_name: str,
    spec: Dict[str, Any],
    request_payload: Dict[str, Any],
    article_id: str,
    provider_cfg: Dict[str, Any],
) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    adapter_cfg = provider_cfg.get("adapter_config") if isinstance(provider_cfg.get("adapter_config"), dict) else {}
    model_id = str(
        adapter_cfg.get("provider_model_id")
        or request_payload.get("model_name")
        or provider_cfg.get("provider_model_id")
        or "veo-3.1-generate-preview"
    ).strip()
    credential_ref = str(adapter_cfg.get("credential_ref") or provider_cfg.get("credential_ref") or "").strip()
    resolved_secret = _resolve_secret_ref_value_lazy(credential_ref) if credential_ref else None
    api_key = _extract_google_api_key(resolved_secret or "")
    endpoint_url = str(
        adapter_cfg.get("endpoint_url")
        or ((provider_cfg.get("http") or {}).get("endpoint_url") if isinstance(provider_cfg.get("http"), dict) else "")
        or "https://generativelanguage.googleapis.com/v1beta"
    ).strip()
    timeout_seconds = 180
    http_cfg = provider_cfg.get("http") if isinstance(provider_cfg.get("http"), dict) else {}
    try:
        timeout_seconds = int(http_cfg.get("timeout_seconds") or 180)
    except (TypeError, ValueError):
        timeout_seconds = 180
    timeout_seconds = max(30, min(timeout_seconds, 900))
    if not api_key:
        assets = [_build_export_asset(article_id, spec)]
        return provider_name, assets, {
            "message": "Google Veo adapter requires credential_ref resolving to an API key.",
            "provider_configured": False,
            "provider": provider_name,
            "credential_ref": credential_ref or None,
        }

    prompt = _build_google_veo_prompt(spec)
    operation_name = ""
    submit_errors: List[str] = []
    response_body: Dict[str, Any] = {}
    active_url = ""
    for candidate_url, body in _google_veo_request_variants(model_id, prompt, endpoint_url):
        active_url = candidate_url
        try:
            response = requests.post(
                candidate_url,
                params={"key": api_key},
                json=body,
                timeout=max(10, min(timeout_seconds, 120)),
            )
            if response.status_code == 404:
                submit_errors.append(f"{candidate_url} -> 404")
                continue
            response.raise_for_status()
            response_body = response.json() if response.content else {}
            operation_name = str(response_body.get("name") or "").strip()
            if operation_name:
                break
            if isinstance(response_body.get("operation"), dict):
                operation_name = str(response_body.get("operation", {}).get("name") or "").strip()
                if operation_name:
                    break
            submit_errors.append(f"{candidate_url} -> missing operation name")
        except Exception as exc:
            submit_errors.append(f"{candidate_url} -> {exc}")
    if not operation_name:
        assets = [_build_export_asset(article_id, spec)]
        return provider_name, assets, {
            "message": f"Google Veo submit failed: {'; '.join(submit_errors) or 'no operation id returned'}",
            "provider_configured": True,
            "provider": provider_name,
            "provider_response": sanitize_payload(response_body),
        }

    operation_url = _normalize_google_operations_url(endpoint_url, operation_name)
    deadline = time.time() + timeout_seconds
    final_operation: Dict[str, Any] = {}
    while time.time() < deadline:
        poll = requests.get(operation_url, params={"key": api_key}, timeout=20)
        poll.raise_for_status()
        body = poll.json() if poll.content else {}
        final_operation = body if isinstance(body, dict) else {}
        if final_operation.get("done") is True:
            break
        time.sleep(3)
    done = bool(final_operation.get("done"))
    if not done:
        assets = [_build_export_asset(article_id, spec)]
        return provider_name, assets, {
            "message": "Google Veo operation timed out before completion.",
            "provider_configured": True,
            "provider": provider_name,
            "operation_name": operation_name,
            "operation_url": operation_url,
            "provider_response": sanitize_payload(final_operation),
        }
    if final_operation.get("error"):
        assets = [_build_export_asset(article_id, spec)]
        return provider_name, assets, {
            "message": f"Google Veo operation failed: {sanitize_payload(final_operation.get('error'))}",
            "provider_configured": True,
            "provider": provider_name,
            "operation_name": operation_name,
            "provider_response": sanitize_payload(final_operation),
        }

    urls = _extract_video_urls(final_operation.get("response") or final_operation)
    unique_urls: List[str] = []
    for url in urls:
        if url not in unique_urls:
            unique_urls.append(url)
    assets: List[Dict[str, Any]] = [{"type": "video", "url": url, "metadata": {"provider": "google_veo"}} for url in unique_urls]
    if not assets:
        assets = [_build_export_asset(article_id, spec)]
    return provider_name, assets, {
        "message": "Google Veo operation completed.",
        "provider_configured": True,
        "provider": provider_name,
        "operation_name": operation_name,
        "operation_url": operation_url,
        "provider_response": sanitize_payload(final_operation),
    }


def render_video(spec: Dict[str, Any], request_payload: Dict[str, Any], article_id: str) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    provider_cfg = request_payload.get("video_provider_config") if isinstance(request_payload.get("video_provider_config"), dict) else {}
    rendering_mode = str(provider_cfg.get("rendering_mode") or "").strip().lower()
    provider = str(
        request_payload.get("provider")
        or provider_cfg.get("provider")
        or os.environ.get("XYENCE_VIDEO_PROVIDER")
        or "unknown"
    ).strip().lower() or "unknown"
    sanitized_payload = sanitize_payload(request_payload)
    if rendering_mode == "export_package_only":
        assets = [_build_export_asset(article_id, spec)]
        return "export_package", assets, {
            "message": "Rendering mode is export_package_only. No external rendering performed.",
            "provider_configured": True,
            "rendering_mode": rendering_mode,
            "request": sanitized_payload,
        }
    if provider in {"", "unknown", "stub", "none"}:
        assets = [_build_export_asset(article_id, spec)]
        return "unknown", assets, {
            "message": "Video provider is not configured. Generated export package placeholder.",
            "provider_configured": False,
            "rendering_mode": rendering_mode or "unknown",
            "request": sanitized_payload,
        }

    adapter_id = str(provider_cfg.get("adapter_id") or "").strip().lower()
    if rendering_mode == "render_via_adapter" and adapter_id == "google_veo":
        try:
            return _render_via_google_veo(
                provider_name=provider if provider not in {"http", "http_adapter"} else "google_veo",
                spec=spec,
                request_payload=request_payload,
                article_id=article_id,
                provider_cfg=provider_cfg,
            )
        except Exception as exc:
            assets = [_build_export_asset(article_id, spec)]
            return "google_veo", assets, {
                "message": f"Google Veo adapter request failed: {exc}",
                "provider_configured": True,
                "provider": "google_veo",
                "request": sanitized_payload,
            }

    if provider in {"http", "http_adapter"} or rendering_mode in {"render_via_endpoint", "render_via_adapter"}:
        http_cfg = provider_cfg.get("http") if isinstance(provider_cfg.get("http"), dict) else {}
        endpoint_url = str(http_cfg.get("endpoint_url") or "").strip()
        try:
            timeout_seconds = int(http_cfg.get("timeout_seconds") or 90)
        except (TypeError, ValueError):
            timeout_seconds = 90
        if not endpoint_url:
            assets = [_build_export_asset(article_id, spec)]
            return provider, assets, {
                "message": "HTTP video provider selected but endpoint_url is missing. Generated export package placeholder.",
                "provider_configured": False,
                "rendering_mode": rendering_mode or "render_via_endpoint",
                "request": sanitized_payload,
            }
        try:
            return _render_via_http_provider(
                endpoint_url=endpoint_url,
                timeout_seconds=timeout_seconds,
                provider_name=provider,
                spec=spec,
                request_payload=request_payload,
                article_id=article_id,
            )
        except Exception as exc:
            assets = [_build_export_asset(article_id, spec)]
            return provider, assets, {
                "message": f"HTTP provider request failed: {exc}",
                "provider_configured": True,
                "provider": provider,
                "request": sanitized_payload,
            }

    if provider in {"export_package", "json_export"}:
        assets = [_build_export_asset(article_id, spec)]
        return provider, assets, {
            "message": "Export package generated.",
            "provider_configured": True,
            "provider": provider,
            "rendering_mode": rendering_mode or "export_package_only",
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
