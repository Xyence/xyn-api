"""EMS artifact API router entrypoint.

Provides minimal in-memory Assets + demo device/registration panels.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()
_LOCK = threading.Lock()
_ASSETS: list[dict[str, Any]] = []
_DEVICES: list[dict[str, Any]] = []
_REGISTRATIONS: list[dict[str, Any]] = []


class AssetCreatePayload(BaseModel):
    name: str
    type: str
    location: str
    status: str | None = None


class DeviceCreatePayload(BaseModel):
    mac: str
    serial: str
    model: str
    state: str | None = None
    last_seen: str | None = None


class RegistrationCreatePayload(BaseModel):
    device_id: str
    workspace_id: str
    registered_by: str | None = None


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_demo_rows() -> None:
    with _LOCK:
        if _DEVICES:
            return
        now = datetime.now(timezone.utc)
        rows = [
            {"mac": "00:11:22:33:44:01", "serial": "SN-1001", "model": "XR-Edge-100", "state": "unregistered", "hours_ago": 2},
            {"mac": "00:11:22:33:44:02", "serial": "SN-1002", "model": "XR-Edge-100", "state": "registered", "hours_ago": 5},
            {"mac": "00:11:22:33:44:03", "serial": "SN-1003", "model": "XR-Edge-200", "state": "provisioned", "hours_ago": 8},
            {"mac": "00:11:22:33:44:04", "serial": "SN-1004", "model": "XR-Edge-300", "state": "online", "hours_ago": 1},
            {"mac": "00:11:22:33:44:05", "serial": "SN-1005", "model": "XR-Edge-300", "state": "offline", "hours_ago": 48},
            {"mac": "00:11:22:33:44:06", "serial": "SN-1006", "model": "XR-Edge-200", "state": "registered", "hours_ago": 20},
        ]
        for item in rows:
            created_at = (now - timedelta(hours=int(item["hours_ago"]))).isoformat()
            _DEVICES.append(
                {
                    "id": str(uuid.uuid4()),
                    "mac": item["mac"],
                    "serial": item["serial"],
                    "model": item["model"],
                    "state": item["state"],
                    "last_seen": created_at,
                    "created_at": created_at,
                }
            )
        for device in _DEVICES:
            if device["state"] in {"registered", "provisioned", "online", "offline"}:
                _REGISTRATIONS.append(
                    {
                        "id": str(uuid.uuid4()),
                        "device_id": device["id"],
                        "workspace_id": "demo-workspace",
                        "registered_at": device["created_at"],
                        "registered_by": "demo-operator@xyence.io",
                    }
                )


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


@router.get("/devices")
async def list_devices(state: str | None = None) -> dict[str, list[dict[str, Any]]]:
    _seed_demo_rows()
    desired_state = str(state or "").strip().lower()
    with _LOCK:
        rows = [dict(item) for item in _DEVICES]
    if desired_state:
        rows = [item for item in rows if str(item.get("state") or "").strip().lower() == desired_state]
    return {"items": rows}


@router.post("/devices")
async def create_device(payload: DeviceCreatePayload) -> dict[str, Any]:
    state = str(payload.state or "").strip().lower() or "unregistered"
    last_seen = str(payload.last_seen or "").strip() or _iso_now()
    record = {
        "id": str(uuid.uuid4()),
        "mac": payload.mac.strip(),
        "serial": payload.serial.strip(),
        "model": payload.model.strip(),
        "state": state,
        "last_seen": last_seen,
        "created_at": _iso_now(),
    }
    with _LOCK:
        _DEVICES.append(record)
    return record


@router.get("/status-counts")
async def device_status_counts() -> dict[str, Any]:
    _seed_demo_rows()
    order = ["unregistered", "registered", "provisioned", "online", "offline"]
    counts: dict[str, int] = {key: 0 for key in order}
    with _LOCK:
        for device in _DEVICES:
            key = str(device.get("state") or "").strip().lower()
            if key not in counts:
                counts[key] = 0
            counts[key] += 1
    return {
        "items": [{"state": key, "count": int(counts.get(key) or 0)} for key in sorted(counts.keys(), key=lambda item: order.index(item) if item in order else 999)],
        "total": int(sum(counts.values())),
    }


@router.get("/registrations")
async def registrations_last_hours(hours: int = 24) -> dict[str, Any]:
    _seed_demo_rows()
    bounded_hours = max(1, min(168, int(hours or 24)))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=bounded_hours)
    with _LOCK:
        matching = [dict(item) for item in _REGISTRATIONS if datetime.fromisoformat(str(item.get("registered_at"))) >= cutoff]
    per_hour: dict[str, int] = {}
    for entry in matching:
        ts = datetime.fromisoformat(str(entry.get("registered_at"))).astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        key = ts.isoformat()
        per_hour[key] = int(per_hour.get(key) or 0) + 1
    points = [{"bucket": key, "count": per_hour[key]} for key in sorted(per_hour.keys())]
    return {
        "hours": bounded_hours,
        "summary_count": len(matching),
        "points": points,
        "items": matching,
    }


@router.post("/registrations")
async def create_registration(payload: RegistrationCreatePayload) -> dict[str, Any]:
    record = {
        "id": str(uuid.uuid4()),
        "device_id": payload.device_id,
        "workspace_id": payload.workspace_id,
        "registered_at": _iso_now(),
        "registered_by": str(payload.registered_by or "").strip() or "demo-operator@xyence.io",
    }
    with _LOCK:
        _REGISTRATIONS.append(record)
    return record
