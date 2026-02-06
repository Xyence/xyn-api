from fastapi import APIRouter

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("")
def list_devices():
    return []
