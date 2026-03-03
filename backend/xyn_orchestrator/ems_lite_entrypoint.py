"""EMS artifact API router entrypoint.

Provides a minimal in-memory Assets CRUD for demo use.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()
_LOCK = threading.Lock()
_ASSETS: list[dict[str, Any]] = []


class AssetCreatePayload(BaseModel):
    name: str
    type: str
    location: str
    status: str | None = None


@router.get("/assets")
async def list_assets() -> dict[str, list[dict[str, Any]]]:
    with _LOCK:
        rows = [dict(item) for item in _ASSETS]
    return {"items": rows}


@router.post("/assets")
async def create_asset(payload: AssetCreatePayload) -> dict[str, Any]:
    status = str(payload.status or "").strip() or "active"
    record = {
        "id": str(uuid.uuid4()),
        "name": payload.name.strip(),
        "type": payload.type.strip(),
        "location": payload.location.strip(),
        "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with _LOCK:
        _ASSETS.append(record)
    return record
