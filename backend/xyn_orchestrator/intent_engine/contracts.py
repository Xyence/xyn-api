from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional


FormatOption = ["article", "guide", "tour", "explainer_video"]
DurationOption = ["2m", "5m", "8m", "12m"]


@dataclass
class DraftIntakeContract:
    artifact_type: str
    required_fields_base: List[str]
    optional_fields: List[str]
    default_values: Dict[str, Any] = field(default_factory=dict)
    option_sources: Dict[str, Callable[[], List[Any]]] = field(default_factory=dict)

    def infer_fields(self, *, message: str, inferred_fields: Mapping[str, Any]) -> Dict[str, Any]:
        merged: Dict[str, Any] = dict(inferred_fields or {})
        raw_message = str(message or "")
        prompt = raw_message.lower()
        if not str(merged.get("format") or "").strip():
            if any(token in prompt for token in ["explainer video", "video explainer", "explainer", "video"]):
                merged["format"] = "explainer_video"
            elif "guide" in prompt:
                merged["format"] = "guide"
            elif "tour" in prompt:
                merged["format"] = "tour"

        if not str(merged.get("title") or "").strip():
            # title: "My title" or title is "My title"
            title_match = re.search(r"\btitle\b\s*(?:is|:)\s*[\"']([^\"']+)[\"']", raw_message, flags=re.IGNORECASE)
            if not title_match:
                title_match = re.search(r"\btitle\b\s*(?:is|:)\s*([^\n.;]+)", raw_message, flags=re.IGNORECASE)
            if title_match:
                merged["title"] = str(title_match.group(1)).strip()

        if not str(merged.get("category") or "").strip():
            category_match = re.search(r"\bcategory\b\s*(?:is|:)\s*([a-z0-9_-]+)", prompt, flags=re.IGNORECASE)
            if category_match:
                merged["category"] = str(category_match.group(1)).strip().lower()

        if not str(merged.get("intent") or "").strip():
            # intent: ... or intent is ...
            intent_match = re.search(r"\bintent\b\s*(?:is|:)\s*([^\n]+)", raw_message, flags=re.IGNORECASE)
            if intent_match:
                merged["intent"] = str(intent_match.group(1)).strip().strip(".")
            elif str(merged.get("format") or "").strip().lower() in {"explainer_video", "video_explainer"}:
                # Fallback: for explainer prompts, use the main request sentence as intent.
                sentence_match = re.search(r"(create|make|build|write)\s+an?\s+.*", raw_message, flags=re.IGNORECASE)
                if sentence_match:
                    merged["intent"] = str(sentence_match.group(0)).strip().strip(".")

        if not str(merged.get("duration") or "").strip():
            duration_match = re.search(r"\bduration\b\s*(?:is|:)\s*([0-9]{1,2}m)\b", prompt, flags=re.IGNORECASE)
            if duration_match:
                merged["duration"] = str(duration_match.group(1)).strip().lower()
        return merged

    def merge_defaults(self, values: Mapping[str, Any]) -> Dict[str, Any]:
        merged = dict(self.default_values)
        merged.update({k: v for k, v in (values or {}).items() if v is not None})
        if self.normalize_format(merged.get("format")) == "explainer_video" and not str(merged.get("duration") or "").strip():
            merged["duration"] = "5m"
        return merged

    def normalize_format(self, value: Any) -> str:
        raw = str(value or "").strip().lower()
        if raw in {"video_explainer", "explainer_video"}:
            return "explainer_video"
        if raw in {"article", "guide", "tour", "standard"}:
            return raw if raw in {"article", "guide", "tour"} else "article"
        return "article"

    def required_fields(self, values: Mapping[str, Any]) -> List[str]:
        required = list(self.required_fields_base)
        if self.normalize_format(values.get("format")) == "explainer_video":
            required.append("intent")
        return required

    def missing_fields(self, values: Mapping[str, Any]) -> List[str]:
        missing: List[str] = []
        for field_name in self.required_fields(values):
            value = values.get(field_name)
            if isinstance(value, list):
                if not value:
                    missing.append(field_name)
            elif not str(value or "").strip():
                missing.append(field_name)
        return missing

    def options_for_field(self, field_name: str) -> List[Any]:
        resolver = self.option_sources.get(field_name)
        if not resolver:
            return []
        return list(resolver() or [])

    def options_available(self, field_name: str) -> bool:
        return bool(self.option_sources.get(field_name))


class DraftIntakeContractRegistry:
    def __init__(self, *, category_options_provider: Callable[[], Iterable[Any]]):
        self._contracts: Dict[str, DraftIntakeContract] = {
            "ArticleDraft": DraftIntakeContract(
                artifact_type="ArticleDraft",
                required_fields_base=["title", "category", "format"],
                optional_fields=["tags", "summary", "body", "duration", "intent"],
                default_values={"format": "article"},
                option_sources={
                    "category": lambda: list(category_options_provider() or []),
                    "format": lambda: list(FormatOption),
                    "duration": lambda: list(DurationOption),
                },
            )
        }

    def get(self, artifact_type: str) -> Optional[DraftIntakeContract]:
        return self._contracts.get(str(artifact_type or "").strip())

    def supports(self, artifact_type: str) -> bool:
        return self.get(artifact_type) is not None
