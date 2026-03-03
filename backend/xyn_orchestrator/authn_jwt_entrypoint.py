"""core.authn-jwt artifact API router entrypoint."""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def authn_jwt_health() -> dict[str, Any]:
    return {"ok": True, "artifact": "core.authn-jwt"}


@router.get("/config")
async def authn_jwt_config() -> dict[str, Any]:
    issuer = str(os.getenv("XYN_JWT_ISSUER", "xyn")).strip() or "xyn"
    audience = str(os.getenv("XYN_JWT_AUDIENCE", "app")).strip() or "app"
    jwks_url = str(os.getenv("XYN_JWT_JWKS_URL", "")).strip() or None
    token_ttl_seconds = str(os.getenv("XYN_JWT_TOKEN_TTL_SECONDS", "3600")).strip() or "3600"
    return {
        "issuer": issuer,
        "audience": audience,
        "jwks_url": jwks_url,
        "token_ttl_seconds": token_ttl_seconds,
    }
