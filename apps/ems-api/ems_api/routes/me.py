from fastapi import APIRouter, Depends

from ems_api.auth import require_user

router = APIRouter(prefix="/me", tags=["me"])


@router.get("")
def whoami(user=Depends(require_user)):
    return {
        "sub": user.get("sub"),
        "email": user.get("email"),
        "roles": user.get("roles", []),
        "issuer": user.get("iss"),
        "audience": user.get("aud"),
    }
