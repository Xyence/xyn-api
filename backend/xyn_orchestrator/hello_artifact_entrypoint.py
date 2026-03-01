"""Hello app artifact API router entrypoint for seed kernel role loading."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/ping")
async def hello_ping() -> dict[str, object]:
    return {"ok": True, "app": "hello"}

