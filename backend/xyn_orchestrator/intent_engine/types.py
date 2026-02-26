from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, TypedDict


IntentAction = Literal["CreateDraft", "ProposePatch", "ShowOptions", "ValidateDraft"]
IntentStatus = Literal[
    "DraftReady",
    "MissingFields",
    "ProposedPatch",
    "ValidationError",
    "UnsupportedIntent",
]


class MissingFieldItem(TypedDict):
    field: str
    reason: str
    options_available: bool


class PatchChange(TypedDict):
    field: str
    from_value: Any
    to: Any


class ResolutionResult(TypedDict, total=False):
    status: IntentStatus
    action_type: str
    artifact_type: Optional[str]
    artifact_id: Optional[str]
    summary: str
    missing_fields: List[MissingFieldItem]
    options: List[Any]
    proposed_patch: Dict[str, Any]
    draft_payload: Dict[str, Any]
    validation_errors: List[str]
    next_actions: List[Dict[str, Any]]
    audit: Dict[str, Any]


ALLOWED_ACTIONS = {"CreateDraft", "ProposePatch", "ShowOptions", "ValidateDraft"}
ALLOWED_ARTIFACT_TYPES = {"ArticleDraft"}
PATCHABLE_FIELDS = {
    "title",
    "category",
    "format",
    "intent",
    "duration",
    "scenes",
    "tags",
    "summary",
    "body",
}
