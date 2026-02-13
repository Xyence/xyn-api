import os
import re
from typing import Any, Dict, Optional, Tuple

import boto3

from .models import SecretStore


class SecretStoreError(RuntimeError):
    pass


def _aws_region(store: SecretStore) -> str:
    cfg = store.config_json or {}
    return str(cfg.get("aws_region") or os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "").strip()


def _sanitize_path_segment(value: str) -> str:
    value = (value or "").strip().replace(" ", "-")
    value = re.sub(r"[^a-zA-Z0-9._:/=-]+", "-", value)
    value = value.strip("/")
    return value


def normalize_secret_logical_name(name: str) -> str:
    parts = [segment for segment in str(name or "").split("/") if segment.strip()]
    cleaned = [_sanitize_path_segment(segment) for segment in parts]
    cleaned = [segment for segment in cleaned if segment]
    return "/".join(cleaned)


def build_aws_secret_name(
    store: SecretStore,
    *,
    scope_kind: str,
    logical_name: str,
    scope_path_id: Optional[str] = None,
) -> str:
    cfg = store.config_json or {}
    prefix = str(cfg.get("name_prefix") or "/xyn").strip()
    if not prefix:
        prefix = "/xyn"
    prefix = prefix.rstrip("/")
    scope_kind = (scope_kind or "").strip().lower()
    safe_name = normalize_secret_logical_name(logical_name)
    if not safe_name:
        raise SecretStoreError("secret name is required")
    if scope_kind == "platform":
        path = ["platform", safe_name]
    elif scope_kind == "tenant":
        if not scope_path_id:
            raise SecretStoreError("tenant scope requires scope path")
        path = ["tenants", _sanitize_path_segment(scope_path_id), safe_name]
    elif scope_kind == "user":
        if not scope_path_id:
            raise SecretStoreError("user scope requires scope path")
        path = ["users", _sanitize_path_segment(scope_path_id), safe_name]
    elif scope_kind == "team":
        if not scope_path_id:
            raise SecretStoreError("team scope requires scope path")
        path = ["teams", _sanitize_path_segment(scope_path_id), safe_name]
    else:
        raise SecretStoreError(f"unsupported scope_kind: {scope_kind}")
    return f"{prefix}/{'/'.join(path)}"


def _build_tags(store: SecretStore, scope_kind: str, scope_id: Optional[str], secret_ref_id: str) -> list[Dict[str, str]]:
    cfg = store.config_json or {}
    raw_tags = cfg.get("tags") if isinstance(cfg.get("tags"), dict) else {}
    tags: Dict[str, str] = {str(k): str(v) for k, v in (raw_tags or {}).items()}
    tags.update(
        {
            "xyn:managed": "true",
            "xyn:scope_kind": str(scope_kind),
            "xyn:scope_id": str(scope_id or "platform"),
            "xyn:secret_ref_id": str(secret_ref_id),
        }
    )
    return [{"Key": key, "Value": value} for key, value in tags.items()]


def write_secret_value(
    store: SecretStore,
    *,
    logical_name: str,
    scope_kind: str,
    scope_id: Optional[str],
    scope_path_id: Optional[str],
    secret_ref_id: str,
    value: str,
    description: str = "",
) -> Tuple[str, Dict[str, Any]]:
    if not value:
        raise SecretStoreError("secret value is required")
    if store.kind != "aws_secrets_manager":
        raise SecretStoreError("unsupported secret store kind")
    aws_name = build_aws_secret_name(
        store,
        scope_kind=scope_kind,
        logical_name=logical_name,
        scope_path_id=scope_path_id,
    )
    cfg = store.config_json or {}
    region = _aws_region(store)
    client = boto3.client("secretsmanager", region_name=region) if region else boto3.client("secretsmanager")
    tags = _build_tags(store, scope_kind, scope_id, secret_ref_id)
    kms_key_id = str(cfg.get("kms_key_id") or "").strip()
    aws_response: Dict[str, Any] = {}
    try:
        kwargs: Dict[str, Any] = {
            "Name": aws_name,
            "SecretString": value,
            "Tags": tags,
        }
        if description:
            kwargs["Description"] = description
        if kms_key_id:
            kwargs["KmsKeyId"] = kms_key_id
        aws_response = client.create_secret(**kwargs)
    except client.exceptions.ResourceExistsException:
        aws_response = client.put_secret_value(SecretId=aws_name, SecretString=value)
        try:
            client.tag_resource(SecretId=aws_name, Tags=tags)
        except Exception:
            pass
        if description:
            try:
                client.update_secret(SecretId=aws_name, Description=description)
            except Exception:
                pass
    except Exception as exc:
        raise SecretStoreError(f"secret write failed: {exc.__class__.__name__}") from exc

    arn = str(aws_response.get("ARN") or "")
    if not arn:
        try:
            desc = client.describe_secret(SecretId=aws_name)
            arn = str(desc.get("ARN") or "")
        except Exception:
            arn = ""
    external_ref = arn or aws_name
    return external_ref, {"aws_secret_name": aws_name, "aws_arn": arn}
