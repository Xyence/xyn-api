from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ems_api.auth import require_user
from ems_api.db import get_db
from ems_api.models import Device
from ems_api.rbac import require_roles

router = APIRouter(prefix="/devices", tags=["devices"])


class DeviceIn(BaseModel):
    name: str


@router.get("")
def list_devices(user=Depends(require_user), db: Session = Depends(get_db)):
    devices = db.execute(select(Device)).scalars().all()
    return [{"id": device.id, "name": device.name} for device in devices]


@router.post("")
def create_device(payload: DeviceIn, user=Depends(require_roles("admin")), db: Session = Depends(get_db)):
    device = Device(name=payload.name)
    db.add(device)
    db.commit()
    db.refresh(device)
    return {"id": device.id, "name": device.name}


@router.delete("/{device_id}")
def delete_device(device_id: str, user=Depends(require_roles("admin")), db: Session = Depends(get_db)):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    db.delete(device)
    db.commit()
    return {"id": device.id, "name": device.name}
