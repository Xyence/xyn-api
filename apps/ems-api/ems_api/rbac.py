from typing import Iterable

from fastapi import Depends, HTTPException, status

from ems_api.auth import require_user


def has_role(user: dict, role: str) -> bool:
    return role in (user.get("roles") or [])


def require_roles(*roles: str):
    def _check(user=Depends(require_user)):
        user_roles = set(user.get("roles") or [])
        if not user_roles.intersection(set(roles)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required role: {', '.join(roles)}",
            )
        return user

    return _check
