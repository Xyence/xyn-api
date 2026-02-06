from fastapi import APIRouter, Depends

from ems_api.auth import require_user
from ems_api.rbac import require_roles

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("")
def list_reports(user=Depends(require_roles("admin", "viewer"))):
    return []
