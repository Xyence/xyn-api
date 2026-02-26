from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional

from xyn_orchestrator.models import Artifact

from .contracts import DraftIntakeContractRegistry
from .proposal_provider import IntentContextPackMissingError, IntentProposalProvider
from .types import ALLOWED_ACTIONS, ALLOWED_ARTIFACT_TYPES, ResolutionResult


@dataclass
class ResolutionContext:
    artifact: Optional[Artifact] = None


class IntentResolutionEngine:
    def __init__(self, *, proposal_provider: IntentProposalProvider, contracts: DraftIntakeContractRegistry):
        self.proposal_provider = proposal_provider
        self.contracts = contracts

    def _base_result(self, *, action_type: str, artifact_type: Optional[str], request_id: str, confidence: float, llm_model: str) -> ResolutionResult:
        return {
            "status": "UnsupportedIntent",
            "action_type": action_type,
            "artifact_type": artifact_type,
            "artifact_id": None,
            "summary": "Unsupported intent.",
            "next_actions": [],
            "audit": {
                "request_id": request_id,
                "confidence": confidence,
                "llm_model": llm_model,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }

    @staticmethod
    def _heuristic_proposal(*, message: str, has_context: bool) -> Optional[Dict[str, Any]]:
        prompt = str(message or "").strip().lower()
        if not prompt:
            return None

        if any(token in prompt for token in ["show options", "what categories", "what formats", "available categories", "available formats"]):
            field = "category" if "categor" in prompt else "format" if "format" in prompt else "category"
            return {
                "action_type": "ShowOptions",
                "artifact_type": "ArticleDraft",
                "inferred_fields": {"field": field},
                "confidence": 0.56,
                "_model": "heuristic",
            }

        if has_context and re.search(r"\b(add|set|update|rewrite|change|edit|patch)\b", prompt):
            return {
                "action_type": "ProposePatch",
                "artifact_type": "ArticleDraft",
                "inferred_fields": {},
                "confidence": 0.56,
                "_model": "heuristic",
            }

        create_verbs = re.search(r"\b(create|make|start|new|draft|write|build)\b", prompt)
        artifact_tokens = re.search(r"\b(article|guide|tour|explainer|video)\b", prompt)
        if create_verbs and artifact_tokens:
            inferred_fields: Dict[str, Any] = {}
            if "explainer" in prompt or "video" in prompt:
                inferred_fields["format"] = "explainer_video"
            elif "guide" in prompt:
                inferred_fields["format"] = "guide"
            elif "tour" in prompt:
                inferred_fields["format"] = "tour"
            else:
                inferred_fields["format"] = "article"
            return {
                "action_type": "CreateDraft",
                "artifact_type": "ArticleDraft",
                "inferred_fields": inferred_fields,
                "confidence": 0.56,
                "_model": "heuristic",
            }
        return None

    def resolve(self, *, message: str, context: ResolutionContext) -> tuple[ResolutionResult, Dict[str, Any]]:
        request_id = str(uuid.uuid4())
        artifact_type_hint = "ArticleDraft"
        has_context = context.artifact is not None

        try:
            proposal = self.proposal_provider.propose(
                message=message,
                artifact_type_hint=artifact_type_hint,
                has_artifact_context=has_context,
            )
        except IntentContextPackMissingError as exc:
            result = self._base_result(
                action_type="ValidateDraft",
                artifact_type=artifact_type_hint,
                request_id=request_id,
                confidence=0.0,
                llm_model="",
            )
            result["status"] = "UnsupportedIntent"
            result["summary"] = str(exc)
            result["audit"] = {
                **(result.get("audit") or {}),
                "context_pack_slug": exc.slug,
                "context_pack_version": "",
                "context_pack_hash": "",
            }
            return result, {}
        action_type = str(proposal.get("action_type") or "").strip()
        artifact_type = proposal.get("artifact_type")
        confidence = float(proposal.get("confidence") or 0.0)
        llm_model = str(proposal.get("_model") or "")
        context_pack_slug = str(proposal.get("_context_pack_slug") or "")
        context_pack_version = str(proposal.get("_context_pack_version") or "")
        context_pack_hash = str(proposal.get("_context_pack_hash") or "")

        if confidence < 0.55:
            heuristic = self._heuristic_proposal(message=message, has_context=has_context)
            if heuristic:
                proposal = heuristic
                action_type = str(proposal.get("action_type") or "").strip()
                artifact_type = proposal.get("artifact_type")
                confidence = float(proposal.get("confidence") or confidence)
                llm_model = str(proposal.get("_model") or llm_model)

        result = self._base_result(
            action_type=action_type or "ValidateDraft",
            artifact_type=str(artifact_type) if artifact_type else artifact_type_hint,
            request_id=request_id,
            confidence=confidence,
            llm_model=llm_model,
        )
        result["audit"] = {
            **(result.get("audit") or {}),
            "context_pack_slug": context_pack_slug,
            "context_pack_version": context_pack_version,
            "context_pack_hash": context_pack_hash,
        }

        if action_type not in ALLOWED_ACTIONS:
            result["status"] = "UnsupportedIntent"
            result["summary"] = "Intent action is unsupported."
            return result, proposal

        if action_type in {"CreateDraft", "ProposePatch", "ValidateDraft"}:
            target_type = str(artifact_type or artifact_type_hint)
            if target_type not in ALLOWED_ARTIFACT_TYPES:
                result["status"] = "UnsupportedIntent"
                result["summary"] = "Artifact type is unsupported for intent resolution."
                return result, proposal

        if confidence < 0.55:
            result["status"] = "UnsupportedIntent"
            result["summary"] = "Intent is ambiguous; provide clearer draft instructions."
            result["next_actions"] = [
                {"label": "Show category options", "action": "ShowOptions", "field": "category"},
                {"label": "Show format options", "action": "ShowOptions", "field": "format"},
            ]
            return result, proposal

        inferred_fields = proposal.get("inferred_fields") if isinstance(proposal.get("inferred_fields"), dict) else {}

        if action_type == "ShowOptions":
            field_name = str(inferred_fields.get("field") or proposal.get("field") or "").strip().lower()
            if field_name not in {"category", "format", "duration"}:
                result["status"] = "ValidationError"
                result["summary"] = "Options field is required (category, format, or duration)."
                result["validation_errors"] = ["field must be category|format|duration"]
                return result, proposal
            contract = self.contracts.get("ArticleDraft")
            options = contract.options_for_field(field_name) if contract else []
            result["status"] = "DraftReady"
            result["summary"] = f"Options ready for {field_name}."
            result["options"] = options
            result["next_actions"] = []
            return result, proposal

        contract = self.contracts.get("ArticleDraft")
        if contract is None:
            result["status"] = "UnsupportedIntent"
            result["summary"] = "ArticleDraft intake contract is unavailable."
            return result, proposal

        inferred_fields = contract.infer_fields(message=message, inferred_fields=inferred_fields)
        merged = contract.merge_defaults(inferred_fields)

        if action_type == "ProposePatch":
            if context.artifact is None:
                result["status"] = "ValidationError"
                result["summary"] = "Artifact context is required to propose a patch."
                result["validation_errors"] = ["artifact context missing"]
                return result, proposal
            patch_object = {
                key: value
                for key, value in inferred_fields.items()
                if key in {"title", "category", "format", "intent", "duration", "scenes", "tags", "summary", "body"}
            }
            if not patch_object:
                result["status"] = "ValidationError"
                result["summary"] = "No patch fields were inferred from the intent."
                result["validation_errors"] = ["empty patch"]
                return result, proposal
            from .patch_service import validate_patch, PatchValidationError

            try:
                allowed_categories = [str(opt.get("slug") if isinstance(opt, dict) else opt).strip().lower() for opt in contract.options_for_field("category")]
                normalized_patch, changes = validate_patch(
                    artifact=context.artifact,
                    patch_object=patch_object,
                    allowed_categories=allowed_categories,
                )
            except PatchValidationError as exc:
                result["status"] = "ValidationError"
                result["summary"] = "Patch proposal failed deterministic validation."
                result["validation_errors"] = [str(exc)]
                return result, proposal
            result["status"] = "ProposedPatch"
            result["artifact_id"] = str(context.artifact.id)
            result["summary"] = "Patch proposal is ready for confirmation."
            result["proposed_patch"] = {
                "changes": changes,
                "patch_object": normalized_patch,
                "requires_confirmation": True,
            }
            result["next_actions"] = [{"label": "Apply", "action": "ApplyPatch"}]
            return result, proposal

        if action_type in {"CreateDraft", "ValidateDraft"}:
            normalized_values = dict(merged)
            if "format" in normalized_values:
                normalized_values["format"] = contract.normalize_format(normalized_values.get("format"))
            missing = contract.missing_fields(normalized_values)
            if missing:
                result["status"] = "MissingFields"
                result["summary"] = "Draft requires additional fields before it can proceed."
                result["missing_fields"] = [
                    {
                        "field": field_name,
                        "reason": "required by intake contract",
                        "options_available": contract.options_available(field_name),
                    }
                    for field_name in missing
                ]
                result["next_actions"] = [{"label": "Show options", "action": "ShowOptions"}]
                return result, proposal

            result["status"] = "DraftReady"
            result["summary"] = "Draft payload is ready for apply."
            result["draft_payload"] = {
                "title": str(normalized_values.get("title") or "").strip(),
                "category": str(normalized_values.get("category") or "").strip().lower(),
                "format": str(normalized_values.get("format") or "article"),
                "intent": str(normalized_values.get("intent") or "").strip(),
                "duration": str(normalized_values.get("duration") or "").strip(),
                "tags": normalized_values.get("tags") if isinstance(normalized_values.get("tags"), list) else [],
                "summary": str(normalized_values.get("summary") or ""),
                "body": str(normalized_values.get("body") or ""),
            }
            result["next_actions"] = [{"label": "Create draft", "action": "CreateDraft"}]
            return result, proposal

        result["status"] = "UnsupportedIntent"
        result["summary"] = "Intent action is unsupported."
        return result, proposal
