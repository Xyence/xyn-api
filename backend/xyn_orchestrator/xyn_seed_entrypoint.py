"""Seed artifact entrypoint for mounting xyn-api routes via a FastAPI router proxy."""

from __future__ import annotations

import logging
import os
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

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
    headers = _forward_headers(request.headers.items())
    cookie_header = "; ".join([f"{k}={v}" for k, v in request.cookies.items()])
    if cookie_header:
        headers["Cookie"] = cookie_header
    upstream_request = Request(target, data=body, headers=headers, method=request.method.upper())
    timeout_seconds = float(os.getenv("XYN_API_PROXY_TIMEOUT_SECONDS", "30"))
    try:
        with urlopen(upstream_request, timeout=timeout_seconds) as upstream:
            response_headers = {
                k: v
                for k, v in upstream.headers.items()
                if k.lower() not in {"content-encoding", "transfer-encoding", "connection"}
            }
            payload = upstream.read()
            return Response(content=payload, status_code=upstream.status, headers=response_headers)
    except HTTPError as exc:
        response_headers = {
            k: v
            for k, v in (exc.headers.items() if exc.headers else [])
            if k.lower() not in {"content-encoding", "transfer-encoding", "connection"}
        }
        payload = exc.read() if hasattr(exc, "read") else b""
        return Response(content=payload, status_code=int(exc.code), headers=response_headers)
    except URLError:
        return Response(content=b'{"error":"upstream unavailable"}', status_code=502, media_type="application/json")
