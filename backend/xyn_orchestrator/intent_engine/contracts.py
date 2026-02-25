from __future__ import annotations

from dataclasses import dataclass, field
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
        prompt = str(message or "").lower()
        if not str(merged.get("format") or "").strip():
            if any(token in prompt for token in ["explainer video", "video explainer", "explainer", "video"]):
                merged["format"] = "explainer_video"
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
