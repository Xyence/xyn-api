import os

import requests
from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/auth", tags=["auth"])


def _xyn_base_url() -> str:
    return os.environ.get("EMS_PLATFORM_API_BASE", "https://xyence.io").rstrip("/")


def _oidc_app_id() -> str:
    return os.environ.get("EMS_OIDC_APP_ID", "ems.platform").strip() or "ems.platform"


@router.get("/oidc/config")
def oidc_config():
    try:
        response = requests.get(
            f"{_xyn_base_url()}/xyn/api/auth/oidc/config",
            params={"appId": _oidc_app_id()},
            timeout=10,
        )
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"OIDC config fetch failed: {exc}",
        ) from exc
    if response.status_code >= 400:
        detail = response.text
        try:
            detail = response.json()
        except Exception:
            pass
        raise HTTPException(status_code=response.status_code, detail=detail)
    payload = response.json()
    payload["auth_base_url"] = _xyn_base_url()
    payload["app_id"] = _oidc_app_id()
    return payload
