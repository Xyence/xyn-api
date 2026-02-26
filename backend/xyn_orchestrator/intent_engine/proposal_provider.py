from __future__ import annotations

import json
from abc import ABC, abstractmethod
import hashlib
import time
from typing import Any, Dict, Optional

from jsonschema import Draft202012Validator

from xyn_orchestrator.ai_runtime import AiConfigError, AiInvokeError, invoke_model, resolve_ai_config
from xyn_orchestrator.models import ContextPack

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


class IntentContextPackMissingError(RuntimeError):
    def __init__(self, slug: str):
        super().__init__(f"Xyn Console context pack missing. Seed {slug}.")
        self.slug = slug


class IntentProposalProvider(ABC):
    @abstractmethod
    def propose(self, *, message: str, artifact_type_hint: Optional[str] = None, has_artifact_context: bool = False) -> Dict[str, Any]:
        raise NotImplementedError


class LlmIntentProposalProvider(IntentProposalProvider):
    PURPOSE_SLUG = "documentation"
    CONTEXT_PACK_SLUG = "xyn-console-default"
    _CACHE_TTL_SECONDS = 60
    _context_cache: Dict[str, Any] = {"value": None, "expires_at": 0.0}

    def _system_prompt(self) -> str:
        return "Return strict JSON only."

    def context_pack_meta(self, *, force_refresh: bool = False) -> Dict[str, str]:
        now = time.time()
        cached = self._context_cache.get("value")
        expires_at = float(self._context_cache.get("expires_at") or 0.0)
        if not force_refresh and cached and now < expires_at:
            return dict(cached)

        pack = (
            ContextPack.objects.filter(name=self.CONTEXT_PACK_SLUG, scope="global", is_active=True)
            .order_by("-is_default", "-updated_at")
            .first()
        )
        if not pack:
            raise IntentContextPackMissingError(self.CONTEXT_PACK_SLUG)
        content = str(pack.content_markdown or "").strip()
        if not content:
            raise IntentContextPackMissingError(self.CONTEXT_PACK_SLUG)
        meta = {
            "slug": self.CONTEXT_PACK_SLUG,
            "version": str(pack.version or ""),
            "hash": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "content": content,
        }
        self._context_cache = {"value": meta, "expires_at": now + self._CACHE_TTL_SECONDS}
        return dict(meta)

    def _messages(
        self,
        *,
        message: str,
        artifact_type_hint: Optional[str],
        has_artifact_context: bool,
        developer_prompt: str,
    ) -> list[Dict[str, str]]:
        context = {
            "artifact_type_hint": artifact_type_hint,
            "has_artifact_context": bool(has_artifact_context),
        }
        return [
            {"role": "system", "content": self._system_prompt()},
            {"role": "developer", "content": developer_prompt},
            {"role": "user", "content": json.dumps({"message": message, "context": context}, ensure_ascii=False)},
        ]

    def _repair_messages(
        self,
        *,
        message: str,
        invalid_output: str,
        artifact_type_hint: Optional[str],
        has_artifact_context: bool,
        developer_prompt: str,
    ) -> list[Dict[str, str]]:
        return [
            {
                "role": "system",
                "content": self._system_prompt() + " Previous output was invalid JSON. Repair and return strict JSON.",
            },
            {"role": "developer", "content": developer_prompt},
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

    @staticmethod
    def _attach_meta(parsed: Dict[str, Any], *, model_name: str, context_pack_meta: Dict[str, str]) -> Dict[str, Any]:
        parsed["_model"] = model_name
        parsed["_context_pack_slug"] = context_pack_meta.get("slug", "")
        parsed["_context_pack_version"] = context_pack_meta.get("version", "")
        parsed["_context_pack_hash"] = context_pack_meta.get("hash", "")
        return parsed

    def propose(self, *, message: str, artifact_type_hint: Optional[str] = None, has_artifact_context: bool = False) -> Dict[str, Any]:
        context_pack = self.context_pack_meta()
        developer_prompt = context_pack.get("content", "")
        try:
            resolved = resolve_ai_config(purpose_slug=self.PURPOSE_SLUG)
            first = invoke_model(
                resolved_config=resolved,
                messages=self._messages(
                    message=message,
                    artifact_type_hint=artifact_type_hint,
                    has_artifact_context=has_artifact_context,
                    developer_prompt=developer_prompt,
                ),
            )
            first_content = str(first.get("content") or "").strip()
            parsed = self._parse_and_validate(first_content)
            return self._attach_meta(
                parsed,
                model_name=str(first.get("model") or resolved.get("model_name") or ""),
                context_pack_meta=context_pack,
            )
        except IntentContextPackMissingError:
            raise
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
                        developer_prompt=developer_prompt,
                    ),
                )
                content = str(repaired.get("content") or "").strip()
                parsed = self._parse_and_validate(content)
                return self._attach_meta(
                    parsed,
                    model_name=str(repaired.get("model") or resolved.get("model_name") or ""),
                    context_pack_meta=context_pack,
                )
            except Exception:
                return {
                    "action_type": "ValidateDraft",
                    "artifact_type": artifact_type_hint if artifact_type_hint in ALLOWED_ARTIFACT_TYPES else "ArticleDraft",
                    "inferred_fields": {},
                    "confidence": 0.0,
                    "_model": "",
                    "_context_pack_slug": context_pack.get("slug", ""),
                    "_context_pack_version": context_pack.get("version", ""),
                    "_context_pack_hash": context_pack.get("hash", ""),
                }
