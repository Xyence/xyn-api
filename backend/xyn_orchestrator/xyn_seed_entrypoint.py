"""Seed artifact entrypoint for mounting xyn-api routes via a FastAPI router proxy."""

from __future__ import annotations

import logging
import os
from typing import Iterable

import requests
from fastapi import APIRouter, Request, Response

router = APIRouter()
logger = logging.getLogger(__name__)


def _upstream_base_url() -> str:
    # Canonical var: XYN_API_BASE_URL. Keep deprecated alias for compatibility.
    alias = os.getenv("XYN_API_UPSTREAM_URL", "").strip()
    if alias:
        logger.warning("XYN_API_UPSTREAM_URL is deprecated; use XYN_API_BASE_URL")
        return alias.rstrip("/")
    return os.getenv("XYN_API_BASE_URL", "http://localhost:8000").rstrip("/")


def _forward_headers(items: Iterable[tuple[str, str]]) -> dict[str, str]:
    blocked = {"host", "content-length", "connection"}
    return {k: v for k, v in items if k.lower() not in blocked}


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy_to_xyn_api(path: str, request: Request) -> Response:
    _ = path
    query = request.url.query
    request_path = request.url.path or "/"
    target = f"{_upstream_base_url()}{request_path}"
    if query:
        target = f"{target}?{query}"
    body = await request.body()
    upstream = requests.request(
        method=request.method,
        url=target,
        headers=_forward_headers(request.headers.items()),
        data=body,
        cookies=request.cookies,
        allow_redirects=False,
        timeout=float(os.getenv("XYN_API_PROXY_TIMEOUT_SECONDS", "30")),
    )
    response_headers = {
        k: v
        for k, v in upstream.headers.items()
        if k.lower() not in {"content-encoding", "transfer-encoding", "connection"}
    }
    return Response(content=upstream.content, status_code=upstream.status_code, headers=response_headers)
