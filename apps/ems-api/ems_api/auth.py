import os
from typing import Any, Dict

import jwt
from fastapi import HTTPException, Request, status


def _get_required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Missing required environment variable: {name}",
        )
    return value


def decode_token(token: str) -> Dict[str, Any]:
    secret = _get_required_env("EMS_JWT_SECRET")
    issuer = os.environ.get("EMS_JWT_ISSUER", "xyn-ems")
    audience = os.environ.get("EMS_JWT_AUDIENCE", "ems")
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer=issuer,
        audience=audience,
    )


def require_user(request: Request) -> Dict[str, Any]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    token = auth_header.replace("Bearer ", "", 1).strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    try:
        claims = decode_token(token)
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from exc
    request.state.user = claims
    return claims
