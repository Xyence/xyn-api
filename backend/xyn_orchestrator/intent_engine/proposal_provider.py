from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from jsonschema import Draft202012Validator

from xyn_orchestrator.ai_runtime import AiConfigError, AiInvokeError, invoke_model, resolve_ai_config

from .types import ALLOWED_ACTIONS, ALLOWED_ARTIFACT_TYPES

_PROPOSAL_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "action_type": {"type": "string", "enum": sorted(ALLOWED_ACTIONS)},
        "artifact_type": {
            "anyOf": [
                {"type": "string", "enum": sorted(ALLOWED_ARTIFACT_TYPES)},
                {"type": "null"},
            ]
        },
        "inferred_fields": {"type": "object", "additionalProperties": True},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "field": {"type": "string"},
        "user_message": {"type": "string"},
    },
    "required": ["action_type", "inferred_fields", "confidence"],
    "additionalProperties": False,
}
_VALIDATOR = Draft202012Validator(_PROPOSAL_SCHEMA)


class IntentProposalProvider(ABC):
    @abstractmethod
    def propose(self, *, message: str, artifact_type_hint: Optional[str] = None, has_artifact_context: bool = False) -> Dict[str, Any]:
        raise NotImplementedError


class LlmIntentProposalProvider(IntentProposalProvider):
    PURPOSE_SLUG = "documentation"

    def _base_prompt(self) -> str:
        return (
            "You are Xyn Intent Classifier. Return JSON only. No markdown, no prose.\n"
            "Classify into action_type one of: CreateDraft, ProposePatch, ShowOptions, ValidateDraft.\n"
            "artifact_type must be ArticleDraft or null.\n"
            "inferred_fields must only include keys relevant to ArticleDraft: "
            "title, category, format, intent, duration, tags, summary, body, field.\n"
            "For options requests set action_type=ShowOptions and inferred_fields.field to category|format|duration.\n"
            "For edits against existing artifact context prefer ProposePatch.\n"
            "Output schema: "
            "{\"action_type\":...,\"artifact_type\":...,\"inferred_fields\":{...},\"confidence\":0.0-1.0}."
        )

    def _messages(self, *, message: str, artifact_type_hint: Optional[str], has_artifact_context: bool) -> list[Dict[str, str]]:
        context = {
            "artifact_type_hint": artifact_type_hint,
            "has_artifact_context": bool(has_artifact_context),
        }
        return [
            {"role": "system", "content": self._base_prompt()},
            {"role": "user", "content": json.dumps({"message": message, "context": context}, ensure_ascii=False)},
        ]

    def _repair_messages(self, *, message: str, invalid_output: str, artifact_type_hint: Optional[str], has_artifact_context: bool) -> list[Dict[str, str]]:
        return [
            {
                "role": "system",
                "content": self._base_prompt() + "\nYour previous output was invalid JSON. Repair it and return only JSON.",
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "message": message,
                        "artifact_type_hint": artifact_type_hint,
                        "has_artifact_context": bool(has_artifact_context),
                        "invalid_output": invalid_output,
                    },
                    ensure_ascii=False,
                ),
            },
        ]

    @staticmethod
    def _parse_and_validate(content: str) -> Dict[str, Any]:
        data = json.loads(str(content or "").strip())
        errors = sorted(_VALIDATOR.iter_errors(data), key=lambda e: e.path)
        if errors:
            raise ValueError(errors[0].message)
        return data

    def _invoke(self, messages: list[Dict[str, str]]) -> Dict[str, Any]:
        resolved = resolve_ai_config(purpose_slug=self.PURPOSE_SLUG)
        response = invoke_model(resolved_config=resolved, messages=messages)
        content = str(response.get("content") or "").strip()
        if not content:
            raise AiInvokeError("Empty response from AI model")
        parsed = self._parse_and_validate(content)
        parsed["_model"] = str(response.get("model") or resolved.get("model_name") or "")
        return parsed

    def propose(self, *, message: str, artifact_type_hint: Optional[str] = None, has_artifact_context: bool = False) -> Dict[str, Any]:
        try:
            resolved = resolve_ai_config(purpose_slug=self.PURPOSE_SLUG)
            first = invoke_model(
                resolved_config=resolved,
                messages=self._messages(
                    message=message,
                    artifact_type_hint=artifact_type_hint,
                    has_artifact_context=has_artifact_context,
                ),
            )
            first_content = str(first.get("content") or "").strip()
            parsed = self._parse_and_validate(first_content)
            parsed["_model"] = str(first.get("model") or resolved.get("model_name") or "")
            return parsed
        except (AiConfigError, AiInvokeError, ValueError, json.JSONDecodeError) as first_exc:
            try:
                resolved = resolve_ai_config(purpose_slug=self.PURPOSE_SLUG)
                invalid_output = ""
                if "first_content" in locals():
                    invalid_output = first_content
                elif str(first_exc):
                    invalid_output = str(first_exc)
                repaired = invoke_model(
                    resolved_config=resolved,
                    messages=self._repair_messages(
                        message=message,
                        invalid_output=invalid_output,
                        artifact_type_hint=artifact_type_hint,
                        has_artifact_context=has_artifact_context,
                    ),
                )
                content = str(repaired.get("content") or "").strip()
                parsed = self._parse_and_validate(content)
                parsed["_model"] = str(repaired.get("model") or resolved.get("model_name") or "")
                return parsed
            except Exception:
                return {
                    "action_type": "ValidateDraft",
                    "artifact_type": artifact_type_hint if artifact_type_hint in ALLOWED_ARTIFACT_TYPES else "ArticleDraft",
                    "inferred_fields": {},
                    "confidence": 0.0,
                    "_model": "",
                }
