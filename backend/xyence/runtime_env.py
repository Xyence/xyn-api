"""Runtime environment normalization for xyn-api.

Primary source is process env injected by xyn-seed/compose.
Legacy backend/.env fallback is allowed only for local/dev migration windows.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_BOOTSTRAPPED = False
_LEGACY_WARNED = False


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        values[key] = value
    return values


def _is_local_like() -> bool:
    mode = str(os.getenv("XYN_ENV", "local")).strip().lower()
    if mode in {"local", "dev"}:
        return True
    debug = str(os.getenv("DJANGO_DEBUG", "")).strip().lower()
    return debug in {"1", "true", "yes", "on"}


def _apply_alias(target: str, *aliases: str, default: str = "") -> None:
    if str(os.getenv(target, "")).strip():
        return
    for alias in aliases:
        value = str(os.getenv(alias, "")).strip()
        if value:
            os.environ[target] = value
            return
    if default:
        os.environ[target] = default


def _load_legacy_env_if_allowed() -> None:
    global _LEGACY_WARNED
    if not _is_local_like():
        return
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return
    loaded = 0
    for key, value in _read_env_file(env_path).items():
        if key not in os.environ or str(os.getenv(key, "")).strip() == "":
            os.environ[key] = value
            loaded += 1
    if loaded and not _LEGACY_WARNED:
        logger.warning("Loaded legacy backend/.env values for local/dev fallback; migrate to seed-owned env injection.")
        _LEGACY_WARNED = True


def bootstrap_runtime_env() -> None:
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return

    _load_legacy_env_if_allowed()

    _apply_alias("XYN_ENV", "ENV", default="local")
    _apply_alias("XYN_BASE_DOMAIN", "DOMAIN")
    _apply_alias("XYN_AUTH_MODE", "AUTH_MODE", default="simple")
    _apply_alias("XYN_INTERNAL_TOKEN", "XYENCE_INTERNAL_TOKEN")
    _apply_alias("XYN_JOBS_REDIS_URL", "XYENCE_JOBS_REDIS_URL", default="redis://redis:6379/0")
    _apply_alias("XYN_ASYNC_JOBS_MODE", "XYENCE_ASYNC_JOBS_MODE", default="redis")
    _apply_alias("XYN_INTERNAL_BASE_URL", "XYENCE_INTERNAL_BASE_URL", default="http://backend:8000")
    _apply_alias("XYN_MEDIA_ROOT", "XYENCE_MEDIA_ROOT", default="/app/media")
    _apply_alias("XYN_DEPLOYMENT_STALE_SECONDS", "XYENCE_DEPLOYMENT_STALE_SECONDS", default="900")
    _apply_alias("XYN_RUNTIME_SUBSTRATE", "XYENCE_RUNTIME_SUBSTRATE", default="auto")

    # Canonical auth aliases
    _apply_alias("XYN_OIDC_ISSUER", "OIDC_ISSUER")
    _apply_alias("XYN_OIDC_CLIENT_ID", "OIDC_CLIENT_ID")
    _apply_alias("XYN_OIDC_ALLOWED_DOMAINS", "OIDC_ALLOWED_DOMAINS", "ALLOWED_LOGIN_DOMAINS")
    if str(os.getenv("OIDC_ISSUER", "")).strip() == "" and str(os.getenv("XYN_OIDC_ISSUER", "")).strip():
        os.environ["OIDC_ISSUER"] = os.environ["XYN_OIDC_ISSUER"]
    if str(os.getenv("OIDC_CLIENT_ID", "")).strip() == "" and str(os.getenv("XYN_OIDC_CLIENT_ID", "")).strip():
        os.environ["OIDC_CLIENT_ID"] = os.environ["XYN_OIDC_CLIENT_ID"]
    if str(os.getenv("OIDC_ALLOWED_DOMAINS", "")).strip() == "" and str(os.getenv("XYN_OIDC_ALLOWED_DOMAINS", "")).strip():
        os.environ["OIDC_ALLOWED_DOMAINS"] = os.environ["XYN_OIDC_ALLOWED_DOMAINS"]
    if str(os.getenv("ALLOWED_LOGIN_DOMAINS", "")).strip() == "" and str(os.getenv("XYN_OIDC_ALLOWED_DOMAINS", "")).strip():
        os.environ["ALLOWED_LOGIN_DOMAINS"] = os.environ["XYN_OIDC_ALLOWED_DOMAINS"]

    # Optional AI defaults are consumed by orchestration codepaths.
    _apply_alias("XYN_OPENAI_API_KEY", "OPENAI_API_KEY")
    _apply_alias("XYN_GEMINI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "XYN_GOOGLE_API_KEY")
    _apply_alias("XYN_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY")
    if not str(os.getenv("OPENAI_API_KEY", "")).strip() and str(os.getenv("XYN_OPENAI_API_KEY", "")).strip():
        os.environ["OPENAI_API_KEY"] = os.environ["XYN_OPENAI_API_KEY"]
    if not str(os.getenv("GEMINI_API_KEY", "")).strip() and str(os.getenv("XYN_GEMINI_API_KEY", "")).strip():
        os.environ["GEMINI_API_KEY"] = os.environ["XYN_GEMINI_API_KEY"]
    if not str(os.getenv("XYN_GOOGLE_API_KEY", "")).strip() and str(os.getenv("XYN_GEMINI_API_KEY", "")).strip():
        os.environ["XYN_GOOGLE_API_KEY"] = os.environ["XYN_GEMINI_API_KEY"]
    if not str(os.getenv("ANTHROPIC_API_KEY", "")).strip() and str(os.getenv("XYN_ANTHROPIC_API_KEY", "")).strip():
        os.environ["ANTHROPIC_API_KEY"] = os.environ["XYN_ANTHROPIC_API_KEY"]
    _apply_alias("XYN_AI_PROVIDER")
    _apply_alias("XYN_AI_MODEL")
    _apply_alias("XYN_DEFAULT_MODEL_PROVIDER", "XYN_AI_PROVIDER")
    _apply_alias("XYN_DEFAULT_MODEL_NAME", "XYN_AI_MODEL")

    # Backfill legacy names so unchanged modules keep running during migration.
    legacy_pairs = {
        "XYENCE_INTERNAL_TOKEN": "XYN_INTERNAL_TOKEN",
        "XYENCE_JOBS_REDIS_URL": "XYN_JOBS_REDIS_URL",
        "XYENCE_ASYNC_JOBS_MODE": "XYN_ASYNC_JOBS_MODE",
        "XYENCE_INTERNAL_BASE_URL": "XYN_INTERNAL_BASE_URL",
        "XYENCE_MEDIA_ROOT": "XYN_MEDIA_ROOT",
        "XYENCE_DEPLOYMENT_STALE_SECONDS": "XYN_DEPLOYMENT_STALE_SECONDS",
        "XYENCE_RUNTIME_SUBSTRATE": "XYN_RUNTIME_SUBSTRATE",
    }
    for legacy_key, canonical_key in legacy_pairs.items():
        if not str(os.getenv(legacy_key, "")).strip() and str(os.getenv(canonical_key, "")).strip():
            os.environ[legacy_key] = str(os.getenv(canonical_key, "")).strip()

    logger.info(
        "runtime env resolved env=%s auth=%s ai_provider=%s model=%s",
        os.getenv("XYN_ENV", "local"),
        os.getenv("XYN_AUTH_MODE", "simple"),
        os.getenv("XYN_AI_PROVIDER", "openai"),
        os.getenv("XYN_AI_MODEL", "gpt-5-mini"),
    )

    _BOOTSTRAPPED = True
