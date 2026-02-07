import base64
import hashlib
import json
import os
import subprocess
import tempfile
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import boto3
import requests
from botocore.exceptions import BotoCoreError, ClientError
from jsonschema import Draft202012Validator


INTERNAL_BASE_URL = os.environ.get("XYENCE_INTERNAL_BASE_URL", "http://backend:8000").rstrip("/")
INTERNAL_TOKEN = os.environ.get("XYENCE_INTERNAL_TOKEN", "").strip()
CONTRACTS_ROOT = os.environ.get("XYNSEED_CONTRACTS_ROOT", "/xyn-contracts")
MEDIA_ROOT = os.environ.get("XYENCE_MEDIA_ROOT", "/app/media")
SCHEMA_ROOT = os.environ.get("XYENCE_SCHEMA_ROOT", "/app/schemas")
CODEGEN_WORKDIR = os.environ.get("XYENCE_CODEGEN_WORKDIR", "/tmp/xyn-codegen")
CODEGEN_GIT_NAME = os.environ.get("XYN_CODEGEN_GIT_NAME", "xyn-codegen")
CODEGEN_GIT_EMAIL = os.environ.get("XYN_CODEGEN_GIT_EMAIL", "codegen@xyn.local")
CODEGEN_GIT_TOKEN = os.environ.get("XYENCE_CODEGEN_GIT_TOKEN", "").strip()
CODEGEN_PUSH = os.environ.get("XYN_CODEGEN_PUSH", os.environ.get("XYENCE_CODEGEN_PUSH", "")).strip() == "1"


def _headers() -> Dict[str, str]:
    return {"X-Internal-Token": INTERNAL_TOKEN}


def _get_json(path: str) -> Dict[str, Any]:
    response = requests.get(f"{INTERNAL_BASE_URL}{path}", headers=_headers(), timeout=30)
    response.raise_for_status()
    return response.json()


def _post_json(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.post(
        f"{INTERNAL_BASE_URL}{path}",
        headers={**_headers(), "Content-Type": "application/json"},
        json=payload,
        timeout=60,
    )
    response.raise_for_status()
    return response.json()


def _download_file(path: str) -> bytes:
    response = requests.get(f"{INTERNAL_BASE_URL}{path}", headers=_headers(), timeout=60)
    response.raise_for_status()
    return response.content


def _write_artifact(run_id: str, filename: str, content: str) -> str:
    target_dir = os.path.join(MEDIA_ROOT, "run_artifacts", run_id)
    os.makedirs(target_dir, exist_ok=True)
    file_path = os.path.join(target_dir, filename)
    with open(file_path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return f"/media/run_artifacts/{run_id}/{filename}"


def _get_run_artifacts(run_id: str) -> List[Dict[str, Any]]:
    data = _get_json(f"/xyn/internal/runs/{run_id}/artifacts")
    return data.get("artifacts", [])


def _download_artifact_json(run_id: str, name: str) -> Optional[Dict[str, Any]]:
    artifacts = _get_run_artifacts(run_id)
    match = next((artifact for artifact in artifacts if artifact.get("name") == name), None)
    if not match or not match.get("url"):
        return None
    url = match["url"]
    if url.startswith("http"):
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        return response.json()
    content = _download_file(url)
    return json.loads(content.decode("utf-8"))


def _load_schema(filename: str) -> Dict[str, Any]:
    path = os.path.join(SCHEMA_ROOT, filename)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _validate_schema(payload: Dict[str, Any], filename: str) -> List[str]:
    schema = _load_schema(filename)
    validator = Draft202012Validator(schema)
    errors = []
    for err in validator.iter_errors(payload):
        errors.append(f"{'.'.join(str(p) for p in err.path)}: {err.message}")
    return errors


def _ensure_repo_workspace(repo: Dict[str, Any], workspace_root: str) -> str:
    os.makedirs(workspace_root, exist_ok=True)
    repo_name = repo["name"]
    repo_dir = os.path.join(workspace_root, repo_name)
    if os.path.exists(repo_dir) and os.path.isdir(os.path.join(repo_dir, ".git")):
        return repo_dir
    url = repo["url"]
    if repo.get("auth") == "https_token" and CODEGEN_GIT_TOKEN and url.startswith("https://"):
        url = url.replace("https://", f"https://{CODEGEN_GIT_TOKEN}@")
    os.system(f"rm -rf {repo_dir}")
    os.system(f"git clone --depth 1 --branch {repo.get('ref', 'main')} {url} {repo_dir}")
    return repo_dir


def _git_cmd(repo_dir: str, cmd: str) -> int:
    return os.system(f"cd {repo_dir} && {cmd}")


def _stage_all(repo_dir: str) -> int:
    return _git_cmd(repo_dir, "git add -A")


def _ensure_git_identity(repo_dir: str) -> bool:
    email = os.popen(f"cd {repo_dir} && git config --get user.email").read().strip()
    name = os.popen(f"cd {repo_dir} && git config --get user.name").read().strip()
    ok = True
    if not name:
        ok = _git_cmd(repo_dir, f"git config user.name \"{CODEGEN_GIT_NAME}\"") == 0
    if not email:
        ok = ok and _git_cmd(repo_dir, f"git config user.email \"{CODEGEN_GIT_EMAIL}\"") == 0
    return ok


def _write_file(path: str, content: str, executable: bool = False) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    if executable:
        os.chmod(path, 0o755)


def _collect_git_diff(repo_dir: str) -> str:
    _git_cmd(repo_dir, "git add -A")
    return os.popen(f"cd {repo_dir} && git diff --cached --patch").read()


def _list_changed_files(repo_dir: str) -> List[str]:
    output = os.popen(f"cd {repo_dir} && git diff --cached --name-only").read()
    return [line.strip() for line in output.splitlines() if line.strip()]


def _mark_noop_codegen(
    changes_made: bool, work_item_id: str, errors: List[Dict[str, Any]], verify_ok: bool
) -> tuple[bool, bool]:
    if changes_made:
        return True, False
    errors.append(
        {
            "code": "no_changes",
            "message": "Codegen produced no patches or files (noop).",
            "detail": {"work_item_id": work_item_id, "noop": True},
        }
    )
    if verify_ok:
        return True, True
    return False, False


def _apply_scaffold_for_work_item(work_item: Dict[str, Any], repo_dir: str) -> List[str]:
    path_root = work_item["repo_targets"][0].get("path_root", "").strip("/")
    changed: List[str] = []

    def p(rel: str) -> str:
        return os.path.join(repo_dir, path_root, rel)

    if work_item["id"] == "ems-api-scaffold":
        _write_file(
            p("README.md"),
            """# EMS API

FastAPI scaffold for the EMS platform.

## Run
- `pip install -r requirements.txt`
- `uvicorn ems_api.main:app --reload`
 
## Dev JWT
Set `EMS_JWT_SECRET` and issue a dev token:

```bash
export EMS_JWT_SECRET=dev-secret-change-me
python scripts/issue_dev_token.py
```

Use the token to call `/api/me` through nginx:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/me
```
""",
        )
        _write_file(
            p("requirements.txt"),
            """fastapi==0.110.0
uvicorn==0.27.1
PyJWT==2.8.0
""",
        )
        _write_file(
            p("Dockerfile"),
            """FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \\
    && pip install --no-cache-dir -r /app/requirements.txt

COPY ems_api /app/ems_api
COPY scripts /app/scripts

EXPOSE 8000

CMD ["uvicorn", "ems_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
""",
        )
        _write_file(
            p("pyproject.toml"),
            """[project]
name = "ems-api"
version = "0.1.0"
description = "EMS API scaffold"
requires-python = ">=3.10"

[project.optional-dependencies]
dev = [
  "pytest==8.1.1",
  "httpx==0.27.0",
]
""",
        )
        _write_file(p("ems_api/__init__.py"), "")
        _write_file(
            p("ems_api/main.py"),
            """from fastapi import FastAPI
from ems_api.routes import health, devices, reports, me

app = FastAPI(title="EMS API")

app.include_router(health.router)
app.include_router(me.router)
app.include_router(devices.router)
app.include_router(reports.router)
""",
        )
        _write_file(
            p("ems_api/routes/__init__.py"),
            "",
        )
        _write_file(
            p("ems_api/auth.py"),
            """import os
from typing import Any, Dict

import jwt
from fastapi import HTTPException, Request, status


def _get_required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Missing required environment variable: {name}",
        )
    return value


def decode_token(token: str) -> Dict[str, Any]:
    secret = _get_required_env("EMS_JWT_SECRET")
    issuer = os.environ.get("EMS_JWT_ISSUER", "xyn-ems")
    audience = os.environ.get("EMS_JWT_AUDIENCE", "ems")
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer=issuer,
        audience=audience,
    )


def require_user(request: Request) -> Dict[str, Any]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    token = auth_header.replace("Bearer ", "", 1).strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    try:
        claims = decode_token(token)
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from exc
    request.state.user = claims
    return claims
""",
        )
        _write_file(
            p("ems_api/routes/health.py"),
            """from fastapi import APIRouter

router = APIRouter()

@router.get("/health")
def health():
    return {"status": "ok"}
""",
        )
        _write_file(
            p("ems_api/routes/me.py"),
            """from fastapi import APIRouter, Depends

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
""",
        )
        _write_file(
            p("ems_api/routes/devices.py"),
            """from fastapi import APIRouter, Depends

from ems_api.auth import require_user

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("")
def list_devices(user=Depends(require_user)):
    return []
""",
        )
        _write_file(
            p("ems_api/routes/reports.py"),
            """from fastapi import APIRouter, Depends

from ems_api.auth import require_user

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("")
def list_reports(user=Depends(require_user)):
    return []
""",
        )
        _write_file(
            p("scripts/issue_dev_token.py"),
            """import os
import time

import jwt


def main() -> None:
    secret = os.environ.get("EMS_JWT_SECRET", "").strip()
    if not secret:
        raise SystemExit("EMS_JWT_SECRET is required")
    issuer = os.environ.get("EMS_JWT_ISSUER", "xyn-ems")
    audience = os.environ.get("EMS_JWT_AUDIENCE", "ems")
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + 3600,
        "sub": "dev-user",
        "email": "dev@example.com",
        "roles": ["admin"],
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    print(token)


if __name__ == "__main__":
    main()
""",
        )
        _write_file(
            p("ems_api/tests/test_health.py"),
            """from fastapi.testclient import TestClient
from ems_api.main import app


def test_health_placeholder():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
""",
        )
        changed.extend(
            [
                "README.md",
                "requirements.txt",
                "Dockerfile",
                "pyproject.toml",
                "ems_api/__init__.py",
                "ems_api/auth.py",
                "ems_api/main.py",
                "ems_api/routes/__init__.py",
                "ems_api/routes/health.py",
                "ems_api/routes/me.py",
                "ems_api/routes/devices.py",
                "ems_api/routes/reports.py",
                "scripts/issue_dev_token.py",
                "ems_api/tests/test_health.py",
            ]
        )
    if work_item["id"] == "ems-api-authn-oidc":
        _write_file(
            p("ems_api/auth/__init__.py"),
            "",
        )
        _write_file(
            p("ems_api/auth/oidc.py"),
            """def oidc_config():
    return {
        'issuer': '<OIDC_ISSUER>',
        'client_id': '<OIDC_CLIENT_ID>',
    }


def login():
    return {"token": "<jwt>"}
""",
        )
        _write_file(
            p("ems_api/deps.py"),
            """def get_current_user():
    return {"sub": "user-1", "roles": ["admin"]}
""",
        )
        _write_file(
            p("ems_api/tests/test_auth.py"),
            """def test_auth_stub():
    assert True
""",
        )
        changed.extend(["ems_api/auth/__init__.py", "ems_api/auth/oidc.py", "ems_api/deps.py", "ems_api/tests/test_auth.py"])
    if work_item["id"] == "ems-api-rbac":
        _write_file(
            p("ems_api/auth/rbac.py"),
            """ROLES = ['admin', 'operator', 'viewer']


def can(role: str, action: str) -> bool:
    if role == 'admin':
        return True
    if role == 'viewer' and action in {'read'}:
        return True
    if role == 'operator' and action in {'read', 'write'}:
        return True
    return False
""",
        )
        _write_file(
            p("ems_api/tests/test_rbac.py"),
            """from ems_api.auth import rbac


def test_rbac_admin():
    assert rbac.can("admin", "write") is True
""",
        )
        changed.extend(["ems_api/auth/rbac.py", "ems_api/tests/test_rbac.py"])
    if work_item["id"] == "ems-api-devices":
        _write_file(
            p("ems_api/routes/devices.py"),
            """from fastapi import APIRouter, Depends

from ems_api.auth import require_user

router = APIRouter(prefix="/devices")

@router.get("/")
def list_devices(user=Depends(require_user)):
    return []

@router.post("/")
def create_device(user=Depends(require_user)):
    return {"id": "device-1"}
""",
        )
        _write_file(
            p("ems_api/tests/test_devices.py"),
            """def test_devices_stub():
    assert True
""",
        )
        changed.extend(["ems_api/routes/devices.py", "ems_api/tests/test_devices.py"])
    if work_item["id"] == "ems-api-reports":
        _write_file(
            p("ems_api/routes/reports.py"),
            """from fastapi import APIRouter, Depends

from ems_api.auth import require_user

from ems_api.rbac import require_roles

router = APIRouter(prefix="/reports")

@router.get("/")
def get_reports(user=Depends(require_roles("admin", "viewer"))):
    return {"summary": "placeholder"}
""",
        )
        _write_file(
            p("ems_api/tests/test_reports.py"),
            """def test_reports_stub():
    assert True
""",
        )
        changed.extend(["ems_api/routes/reports.py", "ems_api/tests/test_reports.py"])
    if work_item["id"] == "ems-dns-route53":
        _write_file(
            p("ems_api/integrations/__init__.py"),
            "",
        )
        _write_file(
            p("ems_api/integrations/route53.py"),
            """def ensure_record(subdomain: str, target: str) -> None:
    # TODO: implement Route53 record management
    return None


def _load_blueprint_metadata(source_run: Optional[str]) -> Dict[str, Any]:
    if not source_run:
        return {}
    payload = _download_artifact_json(source_run, "blueprint_metadata.json")
    if isinstance(payload, dict):
        return payload
    return {}


def _resolve_route53_zone_id(fqdn: str, zone_id: str, zone_name: str) -> str:
    if zone_id:
        return zone_id
    candidate = zone_name
    if not candidate and fqdn:
        parts = fqdn.rstrip(".").split(".")
        if len(parts) >= 2:
            candidate = ".".join(parts[-2:])
    if not candidate:
        raise RuntimeError("Route53 zone_id or zone_name required")
    if not candidate.endswith("."):
        candidate = f"{candidate}."
    client = boto3.client("route53")
    resp = client.list_hosted_zones_by_name(DNSName=candidate, MaxItems="1")
    zones = resp.get("HostedZones", [])
    if not zones:
        raise RuntimeError(f"No hosted zone found for {candidate}")
    zone = zones[0]
    zone_id_full = zone.get("Id", "")
    return zone_id_full.split("/")[-1]


def _resolve_instance_public_ip(instance_id: str, region: str) -> str:
    ec2 = boto3.client("ec2", region_name=region)
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    for reservation in resp.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            public_ip = instance.get("PublicIpAddress")
            if public_ip:
                return public_ip
    raise RuntimeError("Public IP not found for instance")


def _ensure_route53_record(fqdn: str, zone_id: str, target_ip: str, ttl: int = 300) -> Dict[str, Any]:
    client = boto3.client("route53")
    change = client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Comment": "Xyn EMS DNS ensure",
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": fqdn,
                        "Type": "A",
                        "TTL": ttl,
                        "ResourceRecords": [{"Value": target_ip}],
                    },
                }
            ],
        },
    )
    return {
        "change_id": change.get("ChangeInfo", {}).get("Id", ""),
        "status": change.get("ChangeInfo", {}).get("Status", ""),
    }


def _verify_route53_record(fqdn: str, zone_id: str, target_ip: str) -> bool:
    client = boto3.client("route53")
    resp = client.list_resource_record_sets(
        HostedZoneId=zone_id,
        StartRecordName=fqdn,
        StartRecordType="A",
        MaxItems="1",
    )
    records = resp.get("ResourceRecordSets", [])
    if not records:
        return False
    record = records[0]
    if record.get("Name", "").rstrip(".") != fqdn.rstrip("."):
        return False
    values = [item.get("Value") for item in record.get("ResourceRecords", [])]
    return target_ip in values


def _build_remote_deploy_commands(root_dir: str, jwt_secret: str) -> List[str]:
    return [
        "set -euo pipefail",
        "command -v docker >/dev/null 2>&1 || { echo \"missing_docker\"; exit 10; }",
        "docker compose version >/dev/null 2>&1 || { echo \"missing_compose\"; exit 11; }",
        "command -v git >/dev/null 2>&1 || { echo \"missing_git\"; exit 12; }",
        "command -v curl >/dev/null 2>&1 || { echo \"missing_curl\"; exit 13; }",
        f"ROOT={root_dir}",
        "mkdir -p \"$ROOT\"",
        "if [ ! -d \"$ROOT/xyn-api/.git\" ]; then git clone https://github.com/Xyence/xyn-api \"$ROOT/xyn-api\"; fi",
        "if [ ! -d \"$ROOT/xyn-ui/.git\" ]; then git clone https://github.com/Xyence/xyn-ui \"$ROOT/xyn-ui\"; fi",
        "git -C \"$ROOT/xyn-api\" fetch --all",
        "git -C \"$ROOT/xyn-api\" checkout main",
        "git -C \"$ROOT/xyn-api\" pull --ff-only",
        "git -C \"$ROOT/xyn-ui\" fetch --all",
        "git -C \"$ROOT/xyn-ui\" checkout main",
        "git -C \"$ROOT/xyn-ui\" pull --ff-only",
        "docker compose version",
        "docker version",
        f"export XYN_UI_PATH=\"{root_dir}/xyn-ui/apps/ems-ui\"",
        f"export EMS_JWT_SECRET=\"{jwt_secret}\"",
        f"cd \"{root_dir}/xyn-api\"",
        (
            "XYN_UI_PATH=\"$XYN_UI_PATH\" EMS_JWT_SECRET=\"$EMS_JWT_SECRET\" "
            "docker compose -f apps/ems-stack/docker-compose.yml up -d --build"
        ),
        "curl -fsS http://localhost:8080/health",
        "curl -fsS http://localhost:8080/api/health",
    ]


def _resolve_fqdn(metadata: Dict[str, Any]) -> str:
    deploy = metadata.get("deploy") or {}
    fqdn = deploy.get("primary_fqdn") or deploy.get("fqdn")
    if fqdn:
        return str(fqdn)
    environments = metadata.get("environments") or []
    if isinstance(environments, list) and environments:
        env = environments[0] if isinstance(environments[0], dict) else {}
        fqdn = env.get("fqdn")
        if fqdn:
            return str(fqdn)
    return ""


def _public_verify(fqdn: str) -> tuple[bool, List[Dict[str, Any]]]:
    checks = []
    ok = True
    for path, name in [("/health", "public_health"), ("/api/health", "public_api_health")]:
        url = f"http://{fqdn}{path}"
        try:
            response = requests.get(url, timeout=10)
            status_ok = response.status_code == 200
            checks.append({"name": name, "ok": status_ok, "detail": str(response.status_code)})
            ok = ok and status_ok
        except Exception as exc:
            checks.append({"name": name, "ok": False, "detail": str(exc)})
            ok = False
    return ok, checks


def _route53_noop(fqdn: str, zone_id: str, target_ip: str) -> bool:
    return _verify_route53_record(fqdn, zone_id, target_ip)


def _route53_ensure_with_noop(fqdn: str, zone_id: str, target_ip: str) -> Dict[str, Any]:
    already_ok = _route53_noop(fqdn, zone_id, target_ip)
    change_result: Dict[str, Any] = {}
    if not already_ok:
        change_result = _ensure_route53_record(fqdn, zone_id, target_ip)
    verified = _verify_route53_record(fqdn, zone_id, target_ip)
    return {
        "fqdn": fqdn,
        "zone_id": zone_id,
        "public_ip": target_ip,
        "change": change_result,
        "verified": verified,
        "outcome": "noop" if already_ok else "succeeded",
    }


def _run_remote_deploy(
    run_id: str,
    fqdn: str,
    target_instance: Dict[str, Any],
    jwt_secret: str,
) -> Dict[str, Any]:
    started_at = datetime.utcnow().isoformat() + "Z"
    public_ok, public_checks = _public_verify(fqdn) if fqdn else (False, [])
    if public_ok:
        finished_at = datetime.utcnow().isoformat() + "Z"
        return {
            "deploy_result": {
                "schema_version": "deploy_result.v1",
                "target_instance": target_instance,
                "fqdn": fqdn,
                "ssm_command_id": "",
                "outcome": "noop",
                "changes": "No changes (already healthy)",
                "verification": public_checks,
                "started_at": started_at,
                "finished_at": finished_at,
                "errors": [],
            },
            "public_checks": public_checks,
            "ssm_invoked": False,
            "exec_result": {},
        }
    commands = _build_remote_deploy_commands("/opt/xyn/apps/ems", jwt_secret)
    exec_result = _run_ssm_commands(
        target_instance.get("instance_id"),
        target_instance.get("aws_region"),
        commands,
    )
    finished_at = datetime.utcnow().isoformat() + "Z"
    ssm_ok = exec_result.get("invocation_status") == "Success"
    public_ok, public_checks = _public_verify(fqdn) if fqdn else (False, [])
    return {
        "deploy_result": {
            "schema_version": "deploy_result.v1",
            "target_instance": target_instance,
            "fqdn": fqdn,
            "ssm_command_id": exec_result.get("ssm_command_id", ""),
            "outcome": "succeeded" if ssm_ok else "failed",
            "changes": "docker compose up -d --build",
            "verification": public_checks,
            "started_at": started_at,
            "finished_at": finished_at,
            "errors": [],
        },
        "public_checks": public_checks,
        "ssm_invoked": True,
        "exec_result": exec_result,
    }


def _ssm_preflight_check(exec_result: Dict[str, Any]) -> tuple[bool, str, Optional[str]]:
    output = f"{exec_result.get('stdout', '')}\n{exec_result.get('stderr', '')}"
    for token, code in [
        ("missing_docker", "missing_docker"),
        ("missing_compose", "missing_compose"),
        ("missing_git", "missing_git"),
        ("missing_curl", "missing_curl"),
    ]:
        if token in output:
            return False, token, code
    ok = exec_result.get("invocation_status") == "Success"
    return ok, "ok" if ok else "failed", None


def _build_deploy_verification(
    fqdn: str,
    public_checks: List[Dict[str, Any]],
    dns_ok: Optional[bool],
    exec_result: Dict[str, Any],
    ssm_invoked: bool,
) -> List[Dict[str, Any]]:
    checks = list(public_checks)
    if dns_ok is not None:
        checks.append({"name": "dns_record", "ok": dns_ok, "detail": "match" if dns_ok else "mismatch"})
    if not ssm_invoked:
        checks.append({"name": "ssm_preflight", "ok": True, "detail": "skipped"})
        checks.append({"name": "ssm_local_health", "ok": True, "detail": "skipped"})
        return checks
    preflight_ok, preflight_detail, _ = _ssm_preflight_check(exec_result)
    checks.append({"name": "ssm_preflight", "ok": preflight_ok, "detail": preflight_detail})
    ssm_local_ok = exec_result.get("invocation_status") == "Success"
    checks.append({"name": "ssm_local_health", "ok": ssm_local_ok, "detail": exec_result.get("invocation_status", "")})
    return checks
""",
        )
        _write_file(
            p("ems_api/tests/test_route53.py"),
            """def test_route53_stub():
    assert True
""",
        )
        changed.extend(
            [
                "ems_api/integrations/__init__.py",
                "ems_api/integrations/route53.py",
                "ems_api/tests/test_route53.py",
            ]
        )
    if work_item["id"] == "ems-deploy-compose":
        _write_file(
            p("deploy/docker-compose.yml"),
            """version: '3.9'
services:
  ems-api:
    image: ems-api:latest
    ports:
      - '8000:8000'
  ems-ui:
    image: ems-ui:latest
    ports:
      - '3000:80'
""",
        )
        _write_file(
            p("deploy/README.md"),
            """# EMS Deploy

This folder contains docker-compose and nginx scaffolds.
""",
        )
        _write_file(
            p("deploy/nginx.conf"),
            """server {
  listen 80;
  server_name _;
}
""",
        )
        changed.extend(["deploy/README.md", "deploy/docker-compose.yml", "deploy/nginx.conf"])
    if work_item["id"] == "ems-compose-local-chassis":
        _write_file(
            p("README.md"),
            """# EMS Local Chassis

This stack runs the EMS API + UI locally using Docker Compose.

## Repo Layout
This compose file assumes you have these repos side-by-side:

- `../xyn-api`
- `../xyn-ui`

## Usage
From the `xyn-api` repo root:

```bash
docker compose -f apps/ems-stack/docker-compose.yml up -d --build
```

If your UI repo lives elsewhere, set:

```bash
export XYN_UI_PATH=/absolute/path/to/xyn-ui/apps/ems-ui
```

JWT secret (required for /api/me):

```bash
export EMS_JWT_SECRET=dev-secret-change-me
```

To run with verification checks (Docker required):

```bash
VERIFY_DOCKER=1 docker compose -f apps/ems-stack/docker-compose.yml up -d --build
```

Open:
- http://localhost:8080/
- http://localhost:8080/health
- http://localhost:8080/api/health

To stop:

```bash
docker compose -f apps/ems-stack/docker-compose.yml down -v
```
""",
        )
        _write_file(
            p(".env.example"),
            """POSTGRES_USER=ems
POSTGRES_PASSWORD=ems
POSTGRES_DB=ems
XYN_UI_PATH=../../xyn-ui/apps/ems-ui
EMS_JWT_SECRET=dev-secret-change-me
""",
        )
        _write_file(
            p("docker-compose.yml"),
            """services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-ems}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-ems}
      POSTGRES_DB: ${POSTGRES_DB:-ems}
    volumes:
      - ems_pgdata:/var/lib/postgresql/data

  ems-api:
    build:
      context: ../../apps/ems-api
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgres://${POSTGRES_USER:-ems}:${POSTGRES_PASSWORD:-ems}@postgres:5432/${POSTGRES_DB:-ems}
      EMS_JWT_SECRET: ${EMS_JWT_SECRET:-dev-secret-change-me}
      EMS_JWT_ISSUER: ${EMS_JWT_ISSUER:-xyn-ems}
      EMS_JWT_AUDIENCE: ${EMS_JWT_AUDIENCE:-ems}
    depends_on:
      - postgres
    expose:
      - "8000"

  ems-ui:
    image: node:20-alpine
    working_dir: /app
    volumes:
      - ${XYN_UI_PATH:-../../xyn-ui/apps/ems-ui}:/app
    command: sh -lc "npm install && npm run dev -- --host 0.0.0.0 --port 5173"
    expose:
      - "5173"

  nginx:
    image: nginx:1.27-alpine
    ports:
      - "8080:8080"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - ems-api
      - ems-ui

volumes:
  ems_pgdata: {}
""",
        )
        _write_file(
            p("nginx/nginx.conf"),
            """events {}

http {
  server {
    listen 8080;

    location /health {
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_pass http://ems-api:8000/health;
    }

    location /api/ {
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_pass http://ems-api:8000/;
    }

    location / {
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_pass http://ems-ui:5173/;
    }
  }
}
""",
        )
        _write_file(
            p("scripts/verify.sh"),
            """#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)

if [ "${VERIFY_DOCKER:-}" != "1" ]; then
  echo "VERIFY_DOCKER not set; skipping Docker verification."
  exit 0
fi

cleanup() {
  docker compose -f "$ROOT_DIR/docker-compose.yml" down -v
}

trap cleanup EXIT

docker compose -f "$ROOT_DIR/docker-compose.yml" up -d --build
sleep 2
healthy=0
for i in {1..60}; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health || true)
  if [ "$code" = "200" ]; then
    healthy=1
    break
  fi
  sleep 1
done

if [ "$healthy" -ne 1 ]; then
  echo "Health check failed: /health did not become ready in time."
  docker compose -f "$ROOT_DIR/docker-compose.yml" logs --tail=200 ems-api || true
  docker compose -f "$ROOT_DIR/docker-compose.yml" logs --tail=200 nginx || true
  docker compose -f "$ROOT_DIR/docker-compose.yml" logs --tail=200 ems-ui || true
  exit 1
fi

api_healthy=0
for i in {1..30}; do
  api_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/health || true)
  if [ "$api_code" = "200" ]; then
    api_healthy=1
    break
  fi
  sleep 1
done

if [ "$api_healthy" -ne 1 ]; then
  echo "API health check failed: /api/health did not become ready in time."
  docker compose -f "$ROOT_DIR/docker-compose.yml" logs --tail=200 ems-api || true
  docker compose -f "$ROOT_DIR/docker-compose.yml" logs --tail=200 nginx || true
  exit 1
fi
sleep 2
for i in {1..10}; do
  status_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/me)
  if [ "$status_code" = "401" ]; then
    break
  fi
  sleep 1
done
if [ "$status_code" != "401" ]; then
  echo "Expected /api/me to return 401 without token, got ${status_code}"
  exit 1
fi
viewer_token=$(docker compose -f "$ROOT_DIR/docker-compose.yml" exec -T ems-api python scripts/issue_dev_token.py --role viewer)
for i in {1..10}; do
  viewer_list_code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${viewer_token}" http://localhost:8080/api/devices)
  if [ "$viewer_list_code" = "200" ]; then
    break
  fi
  sleep 1
done
if [ "$viewer_list_code" != "200" ]; then
  echo "Expected viewer GET /api/devices to return 200, got ${viewer_list_code}"
  exit 1
fi
viewer_status=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${viewer_token}" -H "Content-Type: application/json" -d '{"name":"dev-viewer"}' http://localhost:8080/api/devices)
if [ "$viewer_status" != "403" ]; then
  echo "Expected viewer POST /api/devices to return 403, got ${viewer_status}"
  exit 1
fi
admin_token=$(docker compose -f "$ROOT_DIR/docker-compose.yml" exec -T ems-api python scripts/issue_dev_token.py --role admin)
for i in {1..10}; do
  admin_me_code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${admin_token}" http://localhost:8080/api/me)
  if [ "$admin_me_code" = "200" ]; then
    break
  fi
  sleep 1
done
if [ "$admin_me_code" != "200" ]; then
  echo "Expected admin GET /api/me to return 200, got ${admin_me_code}"
  exit 1
fi
admin_post=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${admin_token}" -H "Content-Type: application/json" -d '{"name":"dev1"}' http://localhost:8080/api/devices)
if [ "$admin_post" != "200" ] && [ "$admin_post" != "201" ]; then
  echo "Expected admin POST /api/devices to return 200/201, got ${admin_post}"
  exit 1
fi
admin_list=$(curl -s -H "Authorization: Bearer ${admin_token}" http://localhost:8080/api/devices || true)
echo "$admin_list" | grep -q "dev1"
curl -fsS -H "Authorization: Bearer ${admin_token}" -H "Content-Type: application/json" -d '{"name":"persist1"}' http://localhost:8080/api/devices >/dev/null
docker compose -f "$ROOT_DIR/docker-compose.yml" restart ems-api
for i in {1..30}; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health || true)
  if [ "$code" = "200" ]; then
    break
  fi
  sleep 1
done
curl -fsS -H "Authorization: Bearer ${admin_token}" http://localhost:8080/api/devices | grep -q "persist1"
ui_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/)
if [ "$ui_code" != "200" ] && [ "$ui_code" != "302" ]; then
  echo "Expected UI root to return 200/302, got ${ui_code}"
  exit 1
fi
""",
        )
        os.chmod(p("scripts/verify.sh"), 0o755)
        changed.extend(
            [
                "README.md",
                ".env.example",
                "docker-compose.yml",
                "nginx/nginx.conf",
                "scripts/verify.sh",
            ]
        )
    if work_item["id"] == "ems-authn-jwt-module":
        _write_file(
            p("README.md"),
            """# Module Registry (Local)

This directory holds local module specs that can be seeded into the registry.

- `authn-jwt.json`: JWT verification capability scaffold for EMS.
""",
        )
        _write_file(
            p("authn-jwt.json"),
            """{
  "apiVersion": "xyn.module/v1",
  "kind": "Module",
  "metadata": {
    "name": "authn-jwt",
    "namespace": "core",
    "version": "0.1.0",
    "labels": {
      "capability": "authn.jwt.validate"
    }
  },
  "description": "JWT validation module (HS256) for EMS API services.",
  "module": {
    "type": "lib",
    "fqn": "core.authn-jwt",
    "capabilitiesProvided": [
      "authn.jwt.validate"
    ],
    "interfaces": {
      "config": {
        "EMS_JWT_SECRET": "Shared secret for HS256 verification.",
        "EMS_JWT_ISSUER": "Token issuer (default: xyn-ems).",
        "EMS_JWT_AUDIENCE": "Token audience (default: ems)."
      },
      "claims": {
        "required": ["sub", "email"],
        "optional": ["roles"]
      }
    },
    "dependencies": {}
  }
}
""",
        )
        changed.extend(["README.md", "authn-jwt.json"])
    if work_item["id"] == "ems-authz-rbac-module":
        _write_file(
            p("README.md"),
            """# Module Registry (Local)

This directory holds local module specs that can be seeded into the registry.

- `authn-jwt.json`: JWT verification capability scaffold for EMS.
- `authz-rbac.json`: RBAC enforcement capability scaffold for EMS.
""",
        )
        _write_file(
            p("authz-rbac.json"),
            """{
  "apiVersion": "xyn.module/v1",
  "kind": "Module",
  "metadata": {
    "name": "authz-rbac",
    "namespace": "core",
    "version": "0.1.0",
    "labels": {
      "capability": "authz.rbac.enforce"
    }
  },
  "description": "RBAC enforcement helpers for API routes.",
  "module": {
    "type": "lib",
    "fqn": "core.authz-rbac",
    "capabilitiesProvided": [
      "authz.rbac.enforce"
    ],
    "interfaces": {
      "roles": ["admin", "viewer"],
      "policy": "admin: CRUD; viewer: read-only"
    },
    "dependencies": {}
  }
}
""",
        )
        changed.extend(["README.md", "authz-rbac.json"])
    if work_item["id"] == "dns-route53-module":
        _write_file(
            p("README.md"),
            """# Module Registry (Local)

This directory holds local module specs that can be seeded into the registry.

- `authn-jwt.json`: JWT verification capability scaffold for EMS.
- `authz-rbac.json`: RBAC enforcement capability scaffold for EMS.
- `dns-route53.json`: Route53 DNS record management capability scaffold.
""",
        )
        _write_file(
            p("dns-route53.json"),
            """{
  "apiVersion": "xyn.module/v1",
  "kind": "Module",
  "metadata": {
    "name": "dns-route53",
    "namespace": "core",
    "version": "0.1.0",
    "labels": {
      "capability": "dns.route53.records"
    }
  },
  "description": "Route53 DNS record management module (ensure/delete record sets).",
  "module": {
    "type": "lib",
    "fqn": "core.dns-route53",
    "capabilitiesProvided": [
      "dns.route53.records"
    ],
    "interfaces": {
      "config": {
        "zone_id": "Hosted zone ID (preferred).",
        "zone_name": "Hosted zone name (alternative to zone_id).",
        "record_name": "DNS record name to manage.",
        "record_type": "Record type (A, AAAA, CNAME, TXT, etc.).",
        "ttl": "Record TTL seconds (default: 300).",
        "targets": "List of record targets/values.",
        "aws_auth": "Assume instance role or ambient AWS creds; no inline secrets."
      },
      "operations": {
        "ensure_record": "Create or update a record set to desired targets.",
        "delete_record": "Remove the record set if present."
      }
    },
    "dependencies": {}
  }
}
""",
        )
        changed.extend(["README.md", "dns-route53.json"])
    if work_item["id"] == "ems-api-jwt-protect-me":
        _write_file(
            p("requirements.txt"),
            """fastapi==0.110.0
uvicorn==0.27.1
PyJWT==2.8.0
SQLAlchemy==2.0.30
alembic==1.13.1
psycopg[binary]==3.1.19
""",
        )
        _write_file(
            p("ems_api/auth.py"),
            """import os
from typing import Any, Dict

import jwt
from fastapi import HTTPException, Request, status


def _get_required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Missing required environment variable: {name}",
        )
    return value


def decode_token(token: str) -> Dict[str, Any]:
    secret = _get_required_env("EMS_JWT_SECRET")
    issuer = os.environ.get("EMS_JWT_ISSUER", "xyn-ems")
    audience = os.environ.get("EMS_JWT_AUDIENCE", "ems")
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer=issuer,
        audience=audience,
    )


def require_user(request: Request) -> Dict[str, Any]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    token = auth_header.replace("Bearer ", "", 1).strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    try:
        claims = decode_token(token)
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from exc
    request.state.user = claims
    return claims
""",
        )
        _write_file(
            p("ems_api/routes/me.py"),
            """from fastapi import APIRouter, Depends

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
""",
        )
        _write_file(
            p("ems_api/main.py"),
            """from fastapi import FastAPI
from ems_api.routes import health, devices, reports, me

app = FastAPI(title="EMS API")

app.include_router(health.router)
app.include_router(me.router)
app.include_router(devices.router)
app.include_router(reports.router)
""",
        )
        _write_file(
            p("scripts/issue_dev_token.py"),
            """import os
import time

import jwt


def main() -> None:
    secret = os.environ.get("EMS_JWT_SECRET", "").strip()
    if not secret:
        raise SystemExit("EMS_JWT_SECRET is required")
    issuer = os.environ.get("EMS_JWT_ISSUER", "xyn-ems")
    audience = os.environ.get("EMS_JWT_AUDIENCE", "ems")
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + 3600,
        "sub": "dev-user",
        "email": "dev@example.com",
        "roles": ["admin"],
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    print(token)


if __name__ == "__main__":
    main()
""",
        )
        changed.extend(
            [
                "requirements.txt",
                "ems_api/auth.py",
                "ems_api/rbac.py",
                "ems_api/routes/me.py",
                "ems_api/main.py",
                "scripts/issue_dev_token.py",
            ]
        )
    if work_item["id"] == "ems-api-db-foundation":
        _write_file(
            p("ems_api/db.py"),
            """import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError("DATABASE_URL is required")
    return url


def _build_engine():
    url = _database_url()
    connect_args = {}
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    return create_engine(url, future=True, pool_pre_ping=True, connect_args=connect_args)


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
""",
        )
        _write_file(
            p("ems_api/models.py"),
            """import uuid

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
""",
        )
        changed.extend(["ems_api/db.py", "ems_api/models.py"])
    if work_item["id"] == "ems-api-alembic-migrations":
        _write_file(
            p("alembic.ini"),
            """[alembic]
script_location = alembic
sqlalchemy.url = driver://

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
""",
        )
        _write_file(
            p("alembic/env.py"),
            """import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from ems_api.models import Base


config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_url() -> str:
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError("DATABASE_URL is required for migrations")
    return url


def run_migrations_offline():
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
""",
        )
        _write_file(
            p("alembic/versions/20260206_ems_devices.py"),
            '''"""create devices table

Revision ID: 20260206_ems_devices
Revises:
Create Date: 2026-02-06
"""

from alembic import op
import sqlalchemy as sa


revision = "20260206_ems_devices"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("devices")
''',
        )
        changed.extend(
            [
                "alembic.ini",
                "alembic/env.py",
                "alembic/versions/20260206_ems_devices.py",
            ]
        )
    if work_item["id"] == "ems-api-container-startup-migrate":
        _write_file(
            p("scripts/entrypoint.sh"),
            """#!/usr/bin/env sh
set -e

if [ -z "${DATABASE_URL:-}" ]; then
  echo "DATABASE_URL is required"
  exit 1
fi

echo "Running migrations..."
alembic -c /app/alembic.ini upgrade head

echo "Starting API..."
exec uvicorn ems_api.main:app --host 0.0.0.0 --port 8000
""",
        )
        _write_file(
            p("Dockerfile"),
            """FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \\
    && pip install --no-cache-dir -r /app/requirements.txt

COPY ems_api /app/ems_api
COPY scripts /app/scripts
COPY alembic /app/alembic
COPY alembic.ini /app/alembic.ini

EXPOSE 8000

RUN chmod +x /app/scripts/entrypoint.sh

CMD ["/app/scripts/entrypoint.sh"]
""",
        )
        changed.extend(["scripts/entrypoint.sh", "Dockerfile"])
    if work_item["id"] == "ems-api-devices-postgres":
        _write_file(
            p("ems_api/routes/devices.py"),
            """from fastapi import APIRouter, Depends, HTTPException, status
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
""",
        )
        changed.extend(["ems_api/routes/devices.py"])
    if work_item["id"] == "ems-api-devices-rbac":
        _write_file(
            p("ems_api/rbac.py"),
            """from fastapi import Depends, HTTPException, status

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
""",
        )
        _write_file(
            p("ems_api/routes/devices.py"),
            """import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ems_api.auth import require_user
from ems_api.rbac import require_roles

router = APIRouter(prefix="/devices", tags=["devices"])
_DEVICES: dict[str, dict] = {}


class DeviceIn(BaseModel):
    name: str


@router.get("")
def list_devices(user=Depends(require_user)):
    return list(_DEVICES.values())


@router.post("")
def create_device(payload: DeviceIn, user=Depends(require_roles("admin"))):
    device_id = str(uuid.uuid4())
    device = {"id": device_id, "name": payload.name}
    _DEVICES[device_id] = device
    return device


@router.delete("/{device_id}")
def delete_device(device_id: str, user=Depends(require_roles("admin"))):
    if device_id not in _DEVICES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return _DEVICES.pop(device_id)
""",
        )
        changed.extend(["ems_api/rbac.py", "ems_api/routes/devices.py"])
    if work_item["id"] == "ems-token-script-roles":
        _write_file(
            p("scripts/issue_dev_token.py"),
            """import argparse
import os
import time

import jwt


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue a dev JWT for EMS.")
    parser.add_argument("--role", choices=["admin", "viewer"], default="admin")
    args = parser.parse_args()
    secret = os.environ.get("EMS_JWT_SECRET", "").strip()
    if not secret:
        raise SystemExit("EMS_JWT_SECRET is required")
    issuer = os.environ.get("EMS_JWT_ISSUER", "xyn-ems")
    audience = os.environ.get("EMS_JWT_AUDIENCE", "ems")
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + 3600,
        "sub": f"dev-{args.role}",
        "email": f"{args.role}@example.com",
        "roles": [args.role],
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    print(token)


if __name__ == "__main__":
    main()
""",
        )
        changed.extend(["scripts/issue_dev_token.py"])
    if work_item["id"] == "ems-ui-token-input-me-call":
        _write_file(
            p("src/auth/Login.tsx"),
            """import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

export default function Login() {
  const [status, setStatus] = useState<"ok" | "down" | "checking">("checking");
  const [token, setToken] = useState("");
  const [meResult, setMeResult] = useState<string>("");
  const [meIdentity, setMeIdentity] = useState<string>("");
  const meLabel = useMemo(() => (meResult ? "Response:" : "Response will appear here."), [meResult]);

  const checkHealth = useCallback(async () => {
    setStatus("checking");
    try {
      const response = await fetch("/api/health");
      if (!response.ok) {
        setStatus("down");
        return;
      }
      const payload = (await response.json()) as { status?: string };
      setStatus(payload.status === "ok" ? "ok" : "down");
    } catch {
      setStatus("down");
    }
  }, []);

  const callMe = useCallback(async () => {
    setMeResult("");
    setMeIdentity("");
    try {
      const response = await fetch("/api/me", {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) {
        setMeResult(`Unauthorized (${response.status})`);
        return;
      }
      const payload = await response.json();
      if (payload?.email) {
        setMeIdentity(`Logged in as ${payload.email}`);
      } else if (payload?.sub) {
        setMeIdentity(`Logged in as ${payload.sub}`);
      }
      setMeResult(JSON.stringify(payload, null, 2));
    } catch (err) {
      setMeResult(`Request failed: ${String(err)}`);
    }
  }, [token]);

  useEffect(() => {
    checkHealth();
  }, [checkHealth]);

  return (
    <main>
      <h1>Login (OIDC stub)</h1>
      <p>This is a placeholder login view.</p>
      <p>API: {status === "ok" ? "OK" : status === "down" ? "DOWN" : "CHECKING"}</p>
      <button type="button" onClick={checkHealth}>
        Retry
      </button>
      <div>
        <label htmlFor="token-input">JWT Token</label>
        <input
          id="token-input"
          type="text"
          value={token}
          onChange={(event) => setToken(event.target.value)}
          placeholder="Paste token from issue_dev_token.py"
        />
        <button type="button" onClick={callMe}>
          Call /api/me
        </button>
      </div>
      {meIdentity ? <p>{meIdentity}</p> : null}
      <pre>{meLabel}{meResult ? `\n${meResult}` : ""}</pre>
      <Link to="/devices">Continue to Devices</Link>
    </main>
  );
}
""",
        )
        changed.extend(["src/auth/Login.tsx"])
    if work_item["id"] == "ems-stack-pass-jwt-secret-and-verify-me":
        _write_file(
            p(".env.example"),
            """POSTGRES_USER=ems
POSTGRES_PASSWORD=ems
POSTGRES_DB=ems
XYN_UI_PATH=../../xyn-ui/apps/ems-ui
EMS_JWT_SECRET=dev-secret-change-me
""",
        )
        _write_file(
            p("docker-compose.yml"),
            """services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-ems}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-ems}
      POSTGRES_DB: ${POSTGRES_DB:-ems}
    volumes:
      - ems_pgdata:/var/lib/postgresql/data

  ems-api:
    build:
      context: ../../apps/ems-api
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgres://${POSTGRES_USER:-ems}:${POSTGRES_PASSWORD:-ems}@postgres:5432/${POSTGRES_DB:-ems}
      EMS_JWT_SECRET: ${EMS_JWT_SECRET:-dev-secret-change-me}
      EMS_JWT_ISSUER: ${EMS_JWT_ISSUER:-xyn-ems}
      EMS_JWT_AUDIENCE: ${EMS_JWT_AUDIENCE:-ems}
    depends_on:
      - postgres
    expose:
      - "8000"

  ems-ui:
    image: node:20-alpine
    working_dir: /app
    volumes:
      - ${XYN_UI_PATH:-../../xyn-ui/apps/ems-ui}:/app
    command: sh -lc "npm install && npm run dev -- --host 0.0.0.0 --port 5173"
    expose:
      - "5173"

  nginx:
    image: nginx:1.27-alpine
    ports:
      - "8080:8080"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - ems-api
      - ems-ui

volumes:
  ems_pgdata: {}
""",
        )
        _write_file(
            p("scripts/verify.sh"),
            """#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)

if [ "${VERIFY_DOCKER:-}" != "1" ]; then
  echo "VERIFY_DOCKER not set; skipping Docker verification."
  exit 0
fi

cleanup() {
  docker compose -f "$ROOT_DIR/docker-compose.yml" down -v
}

trap cleanup EXIT

docker compose -f "$ROOT_DIR/docker-compose.yml" up -d --build
healthy=0
for i in {1..30}; do
  if curl -fsS http://localhost:8080/health >/dev/null; then
    healthy=1
    break
  fi
  sleep 1
done

if [ "$healthy" -ne 1 ]; then
  echo "Health check failed: /health did not become ready in time."
  exit 1
fi

curl -fsS http://localhost:8080/api/health >/dev/null
status_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/me)
if [ "$status_code" != "401" ]; then
  echo "Expected /api/me to return 401 without token, got ${status_code}"
  exit 1
fi
token=$(docker compose -f "$ROOT_DIR/docker-compose.yml" exec -T ems-api python scripts/issue_dev_token.py)
curl -fsS -H "Authorization: Bearer ${token}" http://localhost:8080/api/me >/dev/null
curl -fsS -o /dev/null -w "%{http_code}\n" http://localhost:8080/ | grep -E "^(200|302)$"
""",
        )
        os.chmod(p("scripts/verify.sh"), 0o755)
        changed.extend([".env.example", "docker-compose.yml", "scripts/verify.sh"])
    if work_item["id"] == "ems-ui-scaffold":
        _write_file(
            p("README.md"),
            """# EMS UI

Scaffold for EMS UI.
""",
        )
        _write_file(
            p("package.json"),
            """{
  "name": "ems-ui",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.22.2"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.2.1",
    "@types/react": "^18.2.66",
    "@types/react-dom": "^18.2.22",
    "typescript": "^5.4.5",
    "vite": "^5.4.0"
  }
}
""",
        )
        _write_file(
            p("tsconfig.json"),
            """{
  "compilerOptions": {
    "target": "ES2020",
    "jsx": "react-jsx",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "strict": true,
    "skipLibCheck": true
  }
}
""",
        )
        _write_file(
            p("vite.config.ts"),
            """import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
});
""",
        )
        _write_file(
            p("index.html"),
            """<!doctype html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>EMS UI</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
""",
        )
        _write_file(
            p("src/main.tsx"),
            """import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
""",
        )
        _write_file(
            p("src/App.tsx"),
            """import { BrowserRouter } from "react-router-dom";
import RoutesView from "./routes";

export default function App() {
  return (
    <BrowserRouter>
      <RoutesView />
    </BrowserRouter>
  );
}
""",
        )
        _write_file(
            p("src/routes.tsx"),
            """import { Routes, Route } from "react-router-dom";
import Login from "./auth/Login";
import DeviceList from "./devices/DeviceList";
import Reports from "./reports/Reports";

export default function RoutesView() {
  return (
    <Routes>
      <Route path="/" element={<Login />} />
      <Route path="/devices" element={<DeviceList />} />
      <Route path="/reports" element={<Reports />} />
    </Routes>
  );
}
""",
        )
        _write_file(
            p("src/auth/Login.tsx"),
            """import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

export default function Login() {
  const [status, setStatus] = useState<"ok" | "down" | "checking">("checking");
  const [token, setToken] = useState("");
  const [meResult, setMeResult] = useState<string>("");
  const [meIdentity, setMeIdentity] = useState<string>("");
  const meLabel = useMemo(() => (meResult ? "Response:" : "Response will appear here."), [meResult]);

  const checkHealth = useCallback(async () => {
    setStatus("checking");
    try {
      const response = await fetch("/api/health");
      if (!response.ok) {
        setStatus("down");
        return;
      }
      const payload = (await response.json()) as { status?: string };
      setStatus(payload.status === "ok" ? "ok" : "down");
    } catch {
      setStatus("down");
    }
  }, []);

  const callMe = useCallback(async () => {
    setMeResult("");
    setMeIdentity("");
    try {
      const response = await fetch("/api/me", {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) {
        setMeResult(`Unauthorized (${response.status})`);
        return;
      }
      const payload = await response.json();
      if (payload?.email) {
        setMeIdentity(`Logged in as ${payload.email}`);
      } else if (payload?.sub) {
        setMeIdentity(`Logged in as ${payload.sub}`);
      }
      setMeResult(JSON.stringify(payload, null, 2));
    } catch (err) {
      setMeResult(`Request failed: ${String(err)}`);
    }
  }, [token]);

  useEffect(() => {
    checkHealth();
  }, [checkHealth]);

  return (
    <main>
      <h1>Login (OIDC stub)</h1>
      <p>This is a placeholder login view.</p>
      <p>API: {status === "ok" ? "OK" : status === "down" ? "DOWN" : "CHECKING"}</p>
      <button type="button" onClick={checkHealth}>
        Retry
      </button>
      <div>
        <label htmlFor="token-input">JWT Token</label>
        <input
          id="token-input"
          type="text"
          value={token}
          onChange={(event) => setToken(event.target.value)}
          placeholder="Paste token from issue_dev_token.py"
        />
        <button type="button" onClick={callMe}>
          Call /api/me
        </button>
      </div>
      {meIdentity ? <p>{meIdentity}</p> : null}
      <pre>{meLabel}{meResult ? `\n${meResult}` : ""}</pre>
      <Link to="/devices">Continue to Devices</Link>
    </main>
  );
}
""",
        )
        _write_file(
            p("src/devices/DeviceList.tsx"),
            """import { Link } from "react-router-dom";

export default function DeviceList() {
  return (
    <main>
      <h1>Devices</h1>
      <ul>
        <li>device-1</li>
        <li>device-2</li>
      </ul>
      <Link to="/reports">View Reports</Link>
    </main>
  );
}
""",
        )
        _write_file(
            p("src/reports/Reports.tsx"),
            """import { Link } from "react-router-dom";

export default function Reports() {
  return (
    <main>
      <h1>Reports</h1>
      <p>Placeholder report data.</p>
      <Link to="/devices">Back to Devices</Link>
    </main>
  );
}
""",
        )
        _write_file(
            p("src/styles.css"),
            """body { font-family: sans-serif; margin: 0; padding: 0; }
""",
        )
        changed.extend(
            [
                "README.md",
                "package.json",
                "tsconfig.json",
                "vite.config.ts",
                "index.html",
                "src/main.tsx",
                "src/App.tsx",
                "src/routes.tsx",
                "src/auth/Login.tsx",
                "src/devices/DeviceList.tsx",
                "src/reports/Reports.tsx",
                "src/styles.css",
            ]
        )
    if work_item["id"] == "ems-ui-auth":
        _write_file(
            p("src/auth/Login.tsx"),
            """export default function Login() {
  return <div>Login</div>;
}
""",
        )
        _write_file(
            p("src/auth/AuthProvider.tsx"),
            """import { ReactNode } from "react";

export function AuthProvider({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
""",
        )
        changed.extend(["src/auth/Login.tsx", "src/auth/AuthProvider.tsx"])
    if work_item["id"] == "ems-ui-devices":
        _write_file(
            p("src/devices/DeviceList.tsx"),
            """export default function DeviceList() {
  return <div>Devices</div>;
}
""",
        )
        _write_file(
            p("src/devices/DeviceDetail.tsx"),
            """export default function DeviceDetail() {
  return <div>Device Detail</div>;
}
""",
        )
        changed.extend(["src/devices/DeviceList.tsx", "src/devices/DeviceDetail.tsx"])
    if work_item["id"] == "ems-ui-reports":
        _write_file(
            p("src/reports/Reports.tsx"),
            """export default function Reports() {
  return <div>Reports</div>;
}
""",
        )
        changed.append("src/reports/Reports.tsx")
    return changed


def _run_ssm_commands(instance_id: str, region: str, commands: List[str]) -> Dict[str, Any]:
    ssm = boto3.client("ssm", region_name=region)
    cmd = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
    )
    command_id = cmd["Command"]["CommandId"]
    out: Optional[Dict[str, Any]] = None
    last_error: Optional[Exception] = None
    started_at = datetime.utcnow().isoformat() + "Z"
    for _ in range(30):
        try:
            out = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            last_error = exc
            time.sleep(1)
            continue
        status = out.get("Status")
        if status in {"Success", "Failed", "TimedOut", "Cancelled"}:
            break
        time.sleep(2)
    if out is None:
        raise last_error or RuntimeError("SSM command invocation not found yet")
    finished_at = datetime.utcnow().isoformat() + "Z"
    stdout = (out.get("StandardOutputContent") or "")[-4000:]
    stderr = (out.get("StandardErrorContent") or "")[-4000:]
    return {
        "ssm_command_id": command_id,
        "invocation_status": out.get("Status"),
        "response_code": out.get("ResponseCode"),
        "stdout": stdout,
        "stderr": stderr,
        "started_at": started_at,
        "finished_at": finished_at,
    }


def _hash_release_plan(plan: Dict[str, Any]) -> str:
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _transcribe_audio(content: bytes, language_code: str) -> Dict[str, Any]:
    from google.cloud import speech  # type: ignore

    client = speech.SpeechClient()
    audio = speech.RecognitionAudio(content=content)
    config = speech.RecognitionConfig(
        language_code=language_code,
        enable_automatic_punctuation=True,
    )
    response = client.recognize(config=config, audio=audio)
    transcripts = []
    confidences = []
    for result in response.results:
        if result.alternatives:
            transcripts.append(result.alternatives[0].transcript)
            confidences.append(result.alternatives[0].confidence)
    transcript_text = "\n".join(transcripts).strip()
    confidence = sum(confidences) / len(confidences) if confidences else None
    return {
        "transcript_text": transcript_text,
        "confidence": confidence,
        "raw_response_json": {"results": [r.to_dict() for r in response.results]},
    }


def _load_contract_schema(name: str) -> Dict[str, Any]:
    path = os.path.join(CONTRACTS_ROOT, "schemas", name)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _schema_for_kind(kind: str) -> str:
    mapping = {
        "solution": "SolutionBlueprintSpec.schema.json",
        "module": "ModuleSpec.schema.json",
        "bundle": "BundleSpec.schema.json",
    }
    return mapping.get(kind, "SolutionBlueprintSpec.schema.json")


def _validate_blueprint(spec: Dict[str, Any], kind: str) -> List[str]:
    schema = _load_contract_schema(_schema_for_kind(kind))
    validator = Draft202012Validator(schema)
    errors = []
    for error in sorted(validator.iter_errors(spec), key=lambda e: e.path):
        path = ".".join(str(p) for p in error.path) if error.path else "root"
        errors.append(f"{path}: {error.message}")
    return errors


def _openai_generate_blueprint(transcript: str, kind: str, context_text: str) -> Optional[Dict[str, Any]]:
    try:
        config = _get_json("/xyn/internal/openai-config")
        api_key = config.get("api_key")
        model = config.get("model")
        if not api_key or not model:
            return None
    except Exception:
        return None
    from openai import OpenAI  # type: ignore

    client = OpenAI(api_key=api_key)
    if kind == "module":
        system_prompt = (
            "You are generating a ModuleSpec JSON for Xyn. "
            "Return ONLY valid JSON matching ModuleSpec schema. "
            "Use apiVersion xyn.module/v1."
        )
    elif kind == "bundle":
        system_prompt = (
            "You are generating a BundleSpec JSON for Xyn. "
            "Return ONLY valid JSON matching BundleSpec schema. "
            "Use apiVersion xyn.bundle/v1."
        )
    else:
        system_prompt = (
            "You are generating a SolutionBlueprintSpec JSON for Xyn. "
            "Return ONLY valid JSON matching SolutionBlueprintSpec schema. "
            "Use apiVersion xyn.blueprint/v1 and include releaseSpec."
        )
    if context_text:
        system_prompt = f"{context_text}\n\n{system_prompt}"
    response = client.responses.create(
        model=model,
        input=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": transcript},
        ],
    )
    try:
        return json.loads(response.output_text)
    except json.JSONDecodeError:
        return None


def transcribe_voice_note(voice_note_id: str) -> None:
    try:
        _post_json(f"/xyn/internal/voice-notes/{voice_note_id}/status", {"status": "transcribing"})
        meta = _get_json(f"/xyn/internal/voice-notes/{voice_note_id}")
        if meta.get("transcript"):
            return
        audio = _download_file(f"/xyn/internal/voice-notes/{voice_note_id}/audio")
        payload = _transcribe_audio(audio, meta.get("language_code", "en-US"))
        _post_json(
            f"/xyn/internal/voice-notes/{voice_note_id}/transcript",
            {"provider": "google_stt", **payload},
        )
    except Exception as exc:
        _post_json(
            f"/xyn/internal/voice-notes/{voice_note_id}/error",
            {"error": str(exc)},
        )


def generate_blueprint_draft(session_id: str) -> None:
    try:
        _post_json(f"/xyn/internal/draft-sessions/{session_id}/status", {"status": "drafting"})
        payload = _get_json(f"/xyn/internal/draft-sessions/{session_id}")
        kind = payload.get("blueprint_kind", "solution")
        context_payload = _post_json(f"/xyn/internal/draft-sessions/{session_id}/context/resolve", {})
        context_text = context_payload.get("effective_context", "")
        transcripts = payload.get("transcripts", [])
        combined = "\n".join(transcripts)
        draft = _openai_generate_blueprint(combined, kind, context_text) if combined else None
        if not draft:
            draft = payload.get("draft") or {}
        errors = _validate_blueprint(draft, kind) if draft else ["Draft generation failed"]
        status = "ready" if not errors else "ready_with_errors"
        _post_json(
            f"/xyn/internal/draft-sessions/{session_id}/draft",
            {
                "draft_json": draft,
                "requirements_summary": combined[:2000],
                "validation_errors": errors,
                "suggested_fixes": [],
                "diff_summary": "Generated from transcript",
                "status": status,
            },
        )
    except Exception as exc:
        _post_json(
            f"/xyn/internal/draft-sessions/{session_id}/error",
            {"error": str(exc)},
        )


def revise_blueprint_draft(session_id: str, instruction: str) -> None:
    try:
        _post_json(f"/xyn/internal/draft-sessions/{session_id}/status", {"status": "drafting"})
        payload = _get_json(f"/xyn/internal/draft-sessions/{session_id}")
        kind = payload.get("blueprint_kind", "solution")
        context_payload = _post_json(f"/xyn/internal/draft-sessions/{session_id}/context/resolve", {})
        context_text = context_payload.get("effective_context", "")
        base_summary = payload.get("requirements_summary", "")
        combined = (base_summary + "\n" + instruction).strip()
        draft = _openai_generate_blueprint(combined, kind, context_text) or payload.get("draft") or {}
        errors = _validate_blueprint(draft, kind) if draft else ["Revision failed"]
        status = "ready" if not errors else "ready_with_errors"
        _post_json(
            f"/xyn/internal/draft-sessions/{session_id}/draft",
            {
                "draft_json": draft,
                "requirements_summary": combined[:2000],
                "validation_errors": errors,
                "suggested_fixes": [],
                "diff_summary": f"Instruction: {instruction}",
                "status": status,
            },
        )
    except Exception as exc:
        _post_json(
            f"/xyn/internal/draft-sessions/{session_id}/error",
            {"error": str(exc)},
        )


def sync_registry(registry_id: str, run_id: str) -> None:
    try:
        _post_json(f"/xyn/internal/runs/{run_id}", {"status": "running", "append_log": "Starting registry sync\n"})
        context = _post_json(
            "/xyn/internal/context-packs/resolve",
            {"purpose": "operator"},
        )
        _post_json(
            f"/xyn/internal/runs/{run_id}",
            {
                "context_pack_refs_json": context.get("context_pack_refs", []),
                "context_hash": context.get("context_hash", ""),
            },
        )
        context_md = context.get("effective_context", "")
        if context_md:
            url_ctx = _write_artifact(run_id, "context_compiled.md", context_md)
            _post_json(
                f"/xyn/internal/runs/{run_id}/artifacts",
                {"name": "context_compiled.md", "kind": "context", "url": url_ctx},
            )
        manifest = json.dumps(
            {
                "context_hash": context.get("context_hash", ""),
                "packs": context.get("context_pack_refs", []),
            },
            indent=2,
        )
        url_manifest = _write_artifact(run_id, "context_manifest.json", manifest)
        _post_json(
            f"/xyn/internal/runs/{run_id}/artifacts",
            {"name": "context_manifest.json", "kind": "context", "url": url_manifest},
        )
        registry = _get_json(f"/xyn/internal/registries/{registry_id}")
        source_url = (registry.get("url") or "").strip()
        snapshot = {
            "id": registry.get("id"),
            "name": registry.get("name"),
            "registry_type": registry.get("registry_type"),
            "source": source_url or "inline",
            "synced_at": datetime.utcnow().isoformat() + "Z",
            "items": [],
        }
        if source_url.startswith("http"):
            response = requests.get(source_url, timeout=30)
            response.raise_for_status()
            content = response.text
            try:
                snapshot["items"] = json.loads(content)
            except json.JSONDecodeError:
                snapshot["raw"] = content
        elif source_url.startswith("file://") or source_url.startswith("/"):
            path = source_url.replace("file://", "")
            with open(path, "r", encoding="utf-8") as handle:
                content = handle.read()
            try:
                snapshot["items"] = json.loads(content)
            except json.JSONDecodeError:
                try:
                    import yaml  # type: ignore

                    snapshot["items"] = yaml.safe_load(content)
                except Exception:
                    snapshot["raw"] = content
        snapshot_content = json.dumps(snapshot, indent=2)
        url = _write_artifact(run_id, "registry_snapshot.json", snapshot_content)
        _post_json(
            f"/xyn/internal/runs/{run_id}/artifacts",
            {"name": "registry_snapshot.json", "kind": "registry_snapshot", "url": url},
        )
        result = _post_json(f"/xyn/internal/registries/{registry_id}/sync", {"status": "active"})
        _post_json(
            f"/xyn/internal/runs/{run_id}",
            {
                "status": "succeeded",
                "append_log": f"Registry sync completed at {result.get('last_sync_at')}\n",
            },
        )
    except Exception as exc:
        try:
            _post_json(f"/xyn/internal/registries/{registry_id}/sync", {"status": "error"})
        except Exception:
            pass
        _post_json(
            f"/xyn/internal/runs/{run_id}",
            {"status": "failed", "error": str(exc), "append_log": f"Registry sync failed: {exc}\n"},
        )


def generate_release_plan(plan_id: str, run_id: str) -> None:
    try:
        _post_json(f"/xyn/internal/runs/{run_id}", {"status": "running", "append_log": "Generating release plan\n"})
        context = _post_json(
            "/xyn/internal/context-packs/resolve",
            {"purpose": "planner"},
        )
        _post_json(
            f"/xyn/internal/runs/{run_id}",
            {
                "context_pack_refs_json": context.get("context_pack_refs", []),
                "context_hash": context.get("context_hash", ""),
            },
        )
        context_md = context.get("effective_context", "")
        if context_md:
            url_ctx = _write_artifact(run_id, "context_compiled.md", context_md)
            _post_json(
                f"/xyn/internal/runs/{run_id}/artifacts",
                {"name": "context_compiled.md", "kind": "context", "url": url_ctx},
            )
        manifest = json.dumps(
            {
                "context_hash": context.get("context_hash", ""),
                "packs": context.get("context_pack_refs", []),
            },
            indent=2,
        )
        url_manifest = _write_artifact(run_id, "context_manifest.json", manifest)
        _post_json(
            f"/xyn/internal/runs/{run_id}/artifacts",
            {"name": "context_manifest.json", "kind": "context", "url": url_manifest},
        )
        plan = _get_json(f"/xyn/internal/release-plans/{plan_id}")
        _post_json(f"/xyn/internal/release-plans/{plan_id}/generate", {})
        release_plan = {
            "id": plan.get("id"),
            "name": plan.get("name"),
            "target": {
                "kind": plan.get("target_kind"),
                "fqn": plan.get("target_fqn"),
            },
            "from_version": plan.get("from_version"),
            "to_version": plan.get("to_version"),
            "milestones": plan.get("milestones_json") or [],
        }
        release_plan_json = json.dumps(release_plan, indent=2)
        release_plan_md = (
            f"# Release Plan: {release_plan.get('name')}\n\n"
            f"- Target: {release_plan['target']['kind']} {release_plan['target']['fqn']}\n"
            f"- From: {release_plan.get('from_version') or 'n/a'}\n"
            f"- To: {release_plan.get('to_version') or 'n/a'}\n\n"
            "## Milestones\n"
        )
        if isinstance(release_plan.get("milestones"), list):
            for milestone in release_plan["milestones"]:
                release_plan_md += f"- {milestone}\n"
        url_json = _write_artifact(run_id, "release_plan.json", release_plan_json)
        url_md = _write_artifact(run_id, "release_plan.md", release_plan_md)
        _post_json(
            f"/xyn/internal/runs/{run_id}/artifacts",
            {"name": "release_plan.json", "kind": "release_plan", "url": url_json},
        )
        _post_json(
            f"/xyn/internal/runs/{run_id}/artifacts",
            {"name": "release_plan.md", "kind": "release_plan", "url": url_md},
        )
        _post_json(
            f"/xyn/internal/runs/{run_id}",
            {
                "status": "succeeded",
                "append_log": (
                    "Release plan generation completed\n"
                    f"Inputs: target={release_plan['target']['kind']} {release_plan['target']['fqn']}, "
                    f"from={release_plan.get('from_version')}, to={release_plan.get('to_version')}\n"
                ),
            },
        )
    except Exception as exc:
        _post_json(
            f"/xyn/internal/runs/{run_id}",
            {"status": "failed", "error": str(exc), "append_log": f"Release plan failed: {exc}\n"},
        )


def run_dev_task(task_id: str, worker_id: str) -> None:
    run_id: Optional[str] = None
    try:
        task = _post_json(f"/xyn/internal/dev-tasks/{task_id}/claim", {"worker_id": worker_id})
        run_id = task.get("result_run")
        if not run_id:
            return
        task_type = task.get("task_type")
        source_run = task.get("source_run")
        input_artifact_key = task.get("input_artifact_key") or "implementation_plan.json"
        source_entity_type = task.get("source_entity_type")
        source_entity_id = task.get("source_entity_id")
        target_instance = task.get("target_instance") or {}
        context_md = task.get("context", "")
        if context_md:
            url_ctx = _write_artifact(run_id, "context_compiled.md", context_md)
            _post_json(
                f"/xyn/internal/runs/{run_id}/artifacts",
                {"name": "context_compiled.md", "kind": "context", "url": url_ctx},
            )
        manifest = json.dumps(
            {"context_hash": task.get("context_hash", ""), "packs": task.get("context_pack_refs", [])},
            indent=2,
        )
        url_manifest = _write_artifact(run_id, "context_manifest.json", manifest)
        _post_json(
            f"/xyn/internal/runs/{run_id}/artifacts",
            {"name": "context_manifest.json", "kind": "context", "url": url_manifest},
        )
        _post_json(
            f"/xyn/internal/runs/{run_id}",
            {"status": "running", "append_log": f"Executing dev task {task_id}\n"},
        )
        _post_json(
            f"/xyn/internal/runs/{run_id}",
            {"append_log": f"Task type: {task.get('task_type')}\n"},
        )
        if task_type == "codegen":
            started_at = datetime.utcnow().isoformat() + "Z"
            plan_json = None
            if source_run:
                plan_json = _download_artifact_json(source_run, input_artifact_key)
            if not plan_json:
                raise RuntimeError("implementation_plan.json not found for codegen task")
            work_item_id = task.get("work_item_id") or ""
            work_item = None
            for item in plan_json.get("work_items", []):
                if item.get("id") == work_item_id:
                    work_item = item
                    break
            if not work_item:
                raise RuntimeError(f"work_item_id not found in plan: {work_item_id}")
            blueprint_metadata = _load_blueprint_metadata(source_run)
            deploy_meta = blueprint_metadata.get("deploy") or {}
            fqdn = _resolve_fqdn(blueprint_metadata)
            dns_provider = blueprint_metadata.get("dns_provider") or deploy_meta.get("dns_provider")
            dns_zone_id = deploy_meta.get("dns_zone_id") or blueprint_metadata.get("dns_zone_id") or ""
            dns_zone_name = deploy_meta.get("dns_zone_name") or blueprint_metadata.get("base_domain") or ""
            jwt_secret = deploy_meta.get("ems_jwt_secret") or os.environ.get("EMS_JWT_SECRET", "dev-secret-change-me")
            workspace_root = os.path.join(CODEGEN_WORKDIR, task_id)
            os.system(f"rm -rf {workspace_root}")
            os.makedirs(workspace_root, exist_ok=True)
            repo_results = []
            repo_result_index = {}
            repo_states = []
            artifacts = []
            errors = []
            success = True
            changes_made = False
            work_item_title = work_item.get("title") or work_item_id
            blueprint_id = plan_json.get("blueprint_id")
            blueprint_name = plan_json.get("blueprint_name") or plan_json.get("blueprint")
            for repo in work_item.get("repo_targets", []):
                repo_dir = _ensure_repo_workspace(repo, workspace_root)
                _apply_scaffold_for_work_item(work_item, repo_dir)
                diff = _collect_git_diff(repo_dir)
                files_changed = _list_changed_files(repo_dir)
                patches = []
                if diff.strip():
                    changes_made = True
                    worktree_dir = tempfile.mkdtemp(prefix="apply-check-", dir=workspace_root)
                    try:
                        wt_proc = subprocess.run(
                            ["git", "worktree", "add", "--detach", worktree_dir, "HEAD"],
                            cwd=repo_dir,
                            capture_output=True,
                            text=True,
                        )
                        if wt_proc.returncode != 0:
                            raise RuntimeError(wt_proc.stderr or wt_proc.stdout or "git worktree add failed")
                        apply_proc = subprocess.run(
                            ["git", "apply", "--check", "-"],
                            input=diff,
                            text=True,
                            cwd=worktree_dir,
                            capture_output=True,
                        )
                        if apply_proc.returncode != 0:
                            err_key = f"patch_apply_error_{repo['name']}.log"
                            err_output = (apply_proc.stderr or "") + (apply_proc.stdout or "")
                            err_url = _write_artifact(run_id, err_key, err_output)
                            _post_json(
                                f"/xyn/internal/runs/{run_id}/artifacts",
                                {"name": err_key, "kind": "codegen", "url": err_url},
                            )
                            errors.append(
                                {
                                    "code": "patch_apply_failed",
                                    "message": "Generated patch failed to apply cleanly.",
                                    "detail": {
                                        "repo": repo.get("name"),
                                        "stderr_artifact": err_key,
                                        "repro_steps": f"cd {worktree_dir} && git apply --check <patch>",
                                    },
                                }
                            )
                            success = False
                    except Exception as exc:
                        errors.append(
                            {
                                "code": "patch_apply_failed",
                                "message": "Patch apply check failed to run.",
                                "detail": {"repo": repo.get("name"), "error": str(exc)},
                            }
                        )
                        success = False
                    finally:
                        subprocess.run(
                            ["git", "worktree", "remove", "--force", worktree_dir],
                            cwd=repo_dir,
                            capture_output=True,
                            text=True,
                        )
                    patch_name = f"codegen_patch_{repo['name']}.diff"
                    patch_url = _write_artifact(run_id, patch_name, diff)
                    artifacts.append(
                        {
                            "key": patch_name,
                            "content_type": "text/x-diff",
                            "description": f"Codegen diff for {repo['name']}",
                        }
                    )
                    _post_json(
                        f"/xyn/internal/runs/{run_id}/artifacts",
                        {"name": patch_name, "kind": "codegen", "url": patch_url},
                    )
                    patches.append({"path_hint": repo.get("path_root", ""), "diff_unified": diff})
                commands_executed = []
                path_root = repo.get("path_root", "").strip("/")
                default_cwd = path_root or "."
                verify_env = os.environ.copy()
                for verify in work_item.get("verify", []):
                    cmd = verify.get("command")
                    cwd = verify.get("cwd") or default_cwd
                    full_cwd = os.path.join(repo_dir, cwd)
                    result_proc = subprocess.run(
                        cmd,
                        shell=True,
                        cwd=full_cwd,
                        env=verify_env,
                        capture_output=True,
                        text=True,
                    )
                    output = (result_proc.stdout or "") + (result_proc.stderr or "")
                    exit_code = result_proc.returncode
                    stdout_key = f"verify_{repo['name']}_{len(commands_executed)}.log"
                    stdout_url = _write_artifact(run_id, stdout_key, output)
                    _post_json(
                        f"/xyn/internal/runs/{run_id}/artifacts",
                        {"name": stdout_key, "kind": "verify", "url": stdout_url},
                    )
                    commands_executed.append(
                        {
                            "command": cmd,
                            "cwd": cwd,
                            "exit_code": int(exit_code),
                            "stdout_artifact": stdout_key,
                            "stderr_artifact": "",
                        }
                    )
                    _post_json(
                        f"/xyn/internal/runs/{run_id}",
                        {
                            "append_log": f"Verify: {cmd} (cwd={cwd}) exit={int(exit_code)}\n",
                        },
                    )
                    expected = verify.get("expect_exit_code", 0)
                    if int(exit_code) != int(expected):
                        success = False
                        errors.append(
                            {
                                "code": "verify_failed",
                                "message": f"Verify failed: {cmd}",
                                "detail": {"exit_code": exit_code, "expected": expected},
                            }
                        )
                repo_entry = {
                    "repo": {
                        "name": repo.get("name"),
                        "url": repo.get("url"),
                        "ref": repo.get("ref"),
                        "path_root": repo.get("path_root"),
                    },
                    "files_changed": files_changed,
                    "patches": patches,
                    "commands_executed": commands_executed,
                    "commit": None,
                }
                repo_results.append(repo_entry)
                repo_key = repo.get("name") or repo.get("url") or str(len(repo_results) - 1)
                repo_result_index[repo_key] = repo_entry
                repo_states.append(
                    {
                        "repo_dir": repo_dir,
                        "repo_name": repo.get("name"),
                        "repo_key": repo_key,
                        "has_changes": bool(diff.strip()),
                    }
                )

            if work_item_id == "dns-route53-ensure-record":
                try:
                    if dns_provider and str(dns_provider).lower() != "route53":
                        raise RuntimeError("dns_provider is not route53")
                    if not fqdn:
                        raise RuntimeError("FQDN missing in blueprint metadata")
                    if not target_instance or not target_instance.get("instance_id"):
                        raise RuntimeError("Target instance missing for DNS ensure")
                    zone_id = _resolve_route53_zone_id(fqdn, dns_zone_id, dns_zone_name)
                    public_ip = _resolve_instance_public_ip(
                        target_instance.get("instance_id"), target_instance.get("aws_region")
                    )
                    dns_result = _route53_ensure_with_noop(fqdn, zone_id, public_ip)
                    ok = bool(dns_result.get("verified"))
                    dns_url = _write_artifact(run_id, "dns_change_result.json", json.dumps(dns_result, indent=2))
                    _post_json(
                        f"/xyn/internal/runs/{run_id}/artifacts",
                        {"name": "dns_change_result.json", "kind": "deploy", "url": dns_url},
                    )
                    artifacts.append(
                        {
                            "key": "dns_change_result.json",
                            "content_type": "application/json",
                            "description": "Route53 change result",
                        }
                    )
                    if not ok:
                        success = False
                        errors.append(
                            {
                                "code": "dns_verify_failed",
                                "message": "Route53 record verification failed.",
                                "detail": {"fqdn": fqdn, "zone_id": zone_id},
                            }
                        )
                except Exception as exc:
                    success = False
                    errors.append(
                        {
                            "code": "route53_failed",
                            "message": "Route53 ensure failed.",
                            "detail": {"error": str(exc)},
                        }
                    )

            if work_item_id == "remote-deploy-compose-ssm":
                deploy_started = datetime.utcnow().isoformat() + "Z"
                try:
                    if not target_instance or not target_instance.get("instance_id"):
                        raise RuntimeError("Target instance missing for remote deploy")
                    dns_ok = None
                    try:
                        if fqdn:
                            zone_id = _resolve_route53_zone_id(fqdn, dns_zone_id, dns_zone_name)
                            public_ip = _resolve_instance_public_ip(
                                target_instance.get("instance_id"), target_instance.get("aws_region")
                            )
                            dns_ok = _verify_route53_record(fqdn, zone_id, public_ip)
                    except Exception:
                        dns_ok = None
                    if fqdn:
                        public_ok, public_checks = _public_verify(fqdn)
                    else:
                        public_ok, public_checks = False, []
                    if public_ok:
                        deploy_finished = datetime.utcnow().isoformat() + "Z"
                        verification = _build_deploy_verification(
                            fqdn, public_checks, dns_ok, {}, False
                        )
                        log_url = _write_artifact(
                            run_id,
                            "deploy_execution.log",
                            json.dumps({"skipped": True, "reason": "already healthy"}, indent=2),
                        )
                        _post_json(
                            f"/xyn/internal/runs/{run_id}/artifacts",
                            {"name": "deploy_execution.log", "kind": "deploy", "url": log_url},
                        )
                        deploy_result = {
                            "schema_version": "deploy_result.v1",
                            "target_instance": target_instance,
                            "fqdn": fqdn,
                            "ssm_command_id": "",
                            "outcome": "noop",
                            "changes": "No changes (already healthy)",
                            "verification": verification,
                            "started_at": deploy_started,
                            "finished_at": deploy_finished,
                            "errors": [],
                        }
                        deploy_url = _write_artifact(
                            run_id, "deploy_result.json", json.dumps(deploy_result, indent=2)
                        )
                        _post_json(
                            f"/xyn/internal/runs/{run_id}/artifacts",
                            {"name": "deploy_result.json", "kind": "deploy", "url": deploy_url},
                        )
                        verify_url = _write_artifact(
                            run_id, "deploy_verify.json", json.dumps({"checks": public_checks}, indent=2)
                        )
                        _post_json(
                            f"/xyn/internal/runs/{run_id}/artifacts",
                            {"name": "deploy_verify.json", "kind": "deploy", "url": verify_url},
                        )
                        artifacts.append(
                            {
                                "key": "deploy_result.json",
                                "content_type": "application/json",
                                "description": "Remote deploy result",
                            }
                        )
                        artifacts.append(
                            {
                                "key": "deploy_verify.json",
                                "content_type": "application/json",
                                "description": "Public verify checks",
                            }
                        )
                        success = True
                    else:
                        deploy_manifest = {
                            "fqdn": fqdn,
                            "target_instance": target_instance,
                            "root_dir": "/opt/xyn/apps/ems",
                            "compose_file": "apps/ems-stack/docker-compose.yml",
                        }
                        manifest_url = _write_artifact(
                            run_id, "deploy_manifest.json", json.dumps(deploy_manifest, indent=2)
                        )
                        _post_json(
                            f"/xyn/internal/runs/{run_id}/artifacts",
                            {"name": "deploy_manifest.json", "kind": "deploy", "url": manifest_url},
                        )
                        deploy_payload = _run_remote_deploy(run_id, fqdn, target_instance, jwt_secret)
                        exec_result = deploy_payload.get("exec_result", {})
                        verification = _build_deploy_verification(
                            fqdn, deploy_payload.get("public_checks", []), dns_ok, exec_result, True
                        )
                        log_payload = {
                            "stdout": exec_result.get("stdout", ""),
                            "stderr": exec_result.get("stderr", ""),
                            "invocation_status": exec_result.get("invocation_status"),
                            "response_code": exec_result.get("response_code"),
                        }
                        log_url = _write_artifact(run_id, "deploy_execution.log", json.dumps(log_payload, indent=2))
                        _post_json(
                            f"/xyn/internal/runs/{run_id}/artifacts",
                            {"name": "deploy_execution.log", "kind": "deploy", "url": log_url},
                        )
                        deploy_result = deploy_payload.get("deploy_result", {})
                        public_checks = deploy_payload.get("public_checks", [])
                        deploy_result["verification"] = verification
                        ssm_ok = deploy_result.get("outcome") == "succeeded"
                        if not ssm_ok:
                            success = False
                            preflight_ok, _, preflight_code = _ssm_preflight_check(exec_result)
                            if preflight_code:
                                deploy_result.setdefault("errors", []).append(
                                    {
                                        "code": preflight_code,
                                        "message": "SSM preflight failed",
                                        "detail": exec_result.get("stderr", ""),
                                    }
                                )
                            elif not preflight_ok:
                                deploy_result.setdefault("errors", []).append(
                                    {
                                        "code": "ssm_preflight_failed",
                                        "message": "SSM preflight failed",
                                        "detail": exec_result.get("stderr", ""),
                                    }
                                )
                            deploy_result.setdefault("errors", []).append(
                                {
                                    "code": "ssm_failed",
                                    "message": "SSM command failed",
                                    "detail": exec_result.get("stderr", ""),
                                }
                            )
                        deploy_url = _write_artifact(
                            run_id, "deploy_result.json", json.dumps(deploy_result, indent=2)
                        )
                        _post_json(
                            f"/xyn/internal/runs/{run_id}/artifacts",
                            {"name": "deploy_result.json", "kind": "deploy", "url": deploy_url},
                        )
                        artifacts.append(
                            {
                                "key": "deploy_result.json",
                                "content_type": "application/json",
                                "description": "Remote deploy result",
                            }
                        )
                        verify_url = _write_artifact(
                            run_id, "deploy_verify.json", json.dumps({"checks": public_checks}, indent=2)
                        )
                        _post_json(
                            f"/xyn/internal/runs/{run_id}/artifacts",
                            {"name": "deploy_verify.json", "kind": "deploy", "url": verify_url},
                        )
                        artifacts.append(
                            {
                                "key": "deploy_verify.json",
                                "content_type": "application/json",
                                "description": "Public verify checks",
                            }
                        )
                except Exception as exc:
                    success = False
                    errors.append(
                        {
                            "code": "remote_deploy_failed",
                            "message": "Remote deploy via SSM failed.",
                            "detail": {"error": str(exc)},
                        }
                    )

            if work_item_id == "remote-deploy-verify-public":
                try:
                    if not fqdn:
                        raise RuntimeError("FQDN missing in blueprint metadata")
                    ok, verify_results = _public_verify(fqdn)
                    if not ok:
                        raise RuntimeError("Public health checks failed")
                    verify_url = _write_artifact(
                        run_id, "deploy_verify.json", json.dumps({"checks": verify_results}, indent=2)
                    )
                    _post_json(
                        f"/xyn/internal/runs/{run_id}/artifacts",
                        {"name": "deploy_verify.json", "kind": "deploy", "url": verify_url},
                    )
                    artifacts.append(
                        {
                            "key": "deploy_verify.json",
                            "content_type": "application/json",
                            "description": "Public verify checks",
                        }
                    )
                except Exception as exc:
                    success = False
                    errors.append(
                        {
                            "code": "public_verify_failed",
                            "message": "Public HTTP verification failed.",
                            "detail": {"error": str(exc)},
                        }
                    )

            if success and changes_made:
                branch_suffix = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
                branch = f"codegen/{work_item_id}/{branch_suffix}"
                commit_message = f"codegen({work_item_id}): {work_item_title}".replace("\"", "'")
                commit_body = None
                if blueprint_id or blueprint_name:
                    commit_body = f"Blueprint: {blueprint_id or ''} {blueprint_name or ''}".strip().replace("\"", "'")
                for state in repo_states:
                    if not state["has_changes"]:
                        continue
                    repo_dir = state["repo_dir"]
                    if _git_cmd(repo_dir, f"git checkout -b {branch}") != 0:
                        success = False
                        errors.append(
                            {
                                "code": "commit_failed",
                                "message": "Failed to create codegen branch.",
                                "detail": {"repo": state["repo_name"], "branch": branch},
                            }
                        )
                        break
                    if not _ensure_git_identity(repo_dir):
                        success = False
                        errors.append(
                            {
                                "code": "commit_failed",
                                "message": "Failed to set git identity for codegen commit.",
                                "detail": {"repo": state["repo_name"], "branch": branch},
                            }
                        )
                        break
                    if _stage_all(repo_dir) != 0:
                        success = False
                        errors.append(
                            {
                                "code": "commit_failed",
                                "message": "Failed to stage changes for commit.",
                                "detail": {"repo": state["repo_name"], "branch": branch},
                            }
                        )
                        break
                    if commit_body:
                        commit_cmd = f"git commit -m \"{commit_message}\" -m \"{commit_body}\""
                    else:
                        commit_cmd = f"git commit -m \"{commit_message}\""
                    commit_rc = _git_cmd(repo_dir, commit_cmd)
                    if commit_rc != 0:
                        success = False
                        errors.append(
                            {
                                "code": "commit_failed",
                                "message": "Failed to create codegen commit.",
                                "detail": {"repo": state["repo_name"], "branch": branch},
                            }
                        )
                        break
                    sha = os.popen(f"cd {repo_dir} && git rev-parse HEAD").read().strip()
                    pushed = False
                    if CODEGEN_PUSH:
                        push_rc = _git_cmd(repo_dir, f"git push -u origin {branch}")
                        if push_rc != 0:
                            success = False
                            errors.append(
                                {
                                    "code": "push_failed",
                                    "message": "Failed to push codegen branch.",
                                    "detail": {"repo": state["repo_name"], "branch": branch},
                                }
                            )
                        else:
                            pushed = True
                    repo_entry = repo_result_index.get(state["repo_key"])
                    if repo_entry is None:
                        success = False
                        errors.append(
                            {
                                "code": "commit_failed",
                                "message": "Failed to locate repo_result entry for commit metadata.",
                                "detail": {"repo": state["repo_name"], "branch": branch},
                            }
                        )
                        break
                    repo_entry["commit"] = {
                        "sha": sha,
                        "message": commit_message,
                        "branch": branch,
                        "pushed": pushed,
                    }
            success, noop = _mark_noop_codegen(changes_made, work_item_id, errors, success)
            result = {
                "schema_version": "codegen_result.v1",
                "task_id": task_id,
                "work_item_id": work_item_id,
                "blueprint_id": plan_json.get("blueprint_id"),
                "summary": {
                    "outcome": "noop" if noop else ("succeeded" if success else "failed"),
                    "changes": "No changes (noop)"
                    if noop
                    else (f"{len(repo_results)} repo(s) updated" if success else "No changes"),
                    "risks": "Scaffolds only; requires implementation.",
                    "next_steps": "Review patches and iterate.",
                },
                "repo_results": repo_results,
                "artifacts": artifacts,
                "success": success,
                "started_at": started_at,
                "finished_at": datetime.utcnow().isoformat() + "Z",
                "errors": errors,
            }
            raw_url = _write_artifact(run_id, "codegen_result_raw.json", json.dumps(result, indent=2))
            _post_json(
                f"/xyn/internal/runs/{run_id}/artifacts",
                {"name": "codegen_result_raw.json", "kind": "codegen", "url": raw_url},
            )
            artifacts.append(
                {
                    "key": "codegen_result_raw.json",
                    "content_type": "application/json",
                    "description": "Raw codegen result before schema validation",
                }
            )
            validation_errors = _validate_schema(result, "codegen_result.v1.schema.json")
            if validation_errors:
                success = False
                result["success"] = False
                result["errors"].append(
                    {"code": "schema_validation", "message": "Invalid codegen_result", "detail": validation_errors}
                )
            url = _write_artifact(run_id, "codegen_result.json", json.dumps(result, indent=2))
            _post_json(
                f"/xyn/internal/runs/{run_id}/artifacts",
                {"name": "codegen_result.json", "kind": "codegen", "url": url},
            )
            _post_json(
                f"/xyn/internal/runs/{run_id}",
                {"status": "succeeded" if success else "failed", "append_log": "Codegen task completed.\n"},
            )
            _post_json(
                f"/xyn/internal/dev-tasks/{task_id}/complete",
                {"status": "succeeded" if success else "failed"},
            )
            return

        if task_type == "release_spec_generate":
            plan_json = None
            if source_run:
                plan_json = _download_artifact_json(source_run, input_artifact_key)
            blueprint_id = plan_json.get("blueprint_id") if plan_json else source_entity_id
            blueprint_fqn = (
                plan_json.get("blueprint_name")
                or plan_json.get("blueprint")
                if plan_json
                else "unknown"
            )
            release_spec = {
                "blueprint_id": blueprint_id,
                "blueprint": blueprint_fqn,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "release_spec": {
                    "name": f"{blueprint_fqn} release spec",
                    "version": "0.1.0",
                    "modules": [],
                },
            }
            url_json = _write_artifact(run_id, "release_spec.json", json.dumps(release_spec, indent=2))
            md = (
                "# Release Spec\n\n"
                f"- Blueprint: {release_spec.get('blueprint')}\n"
                f"- Generated: {release_spec.get('generated_at')}\n\n"
                "## Modules\n"
            )
            url_md = _write_artifact(run_id, "release_spec.md", md)
            _post_json(
                f"/xyn/internal/runs/{run_id}/artifacts",
                {"name": "release_spec.json", "kind": "release_spec", "url": url_json},
            )
            _post_json(
                f"/xyn/internal/runs/{run_id}/artifacts",
                {"name": "release_spec.md", "kind": "release_spec", "url": url_md},
            )
            _post_json(
                f"/xyn/internal/runs/{run_id}",
                {"status": "succeeded", "append_log": "Release spec generated.\n"},
            )
            _post_json(
                f"/xyn/internal/dev-tasks/{task_id}/complete",
                {"status": "succeeded"},
            )
            return

        if task_type == "release_plan_generate":
            plan_json = None
            if source_run:
                plan_json = _download_artifact_json(source_run, input_artifact_key)
            if not plan_json and source_entity_type == "release_plan" and source_entity_id:
                release_plan = _get_json(f"/xyn/internal/release-plans/{source_entity_id}")
                last_run = release_plan.get("last_run")
                if last_run:
                    plan_json = _download_artifact_json(last_run, input_artifact_key)
            if not plan_json:
                plan_json = {
                    "blueprint_id": source_entity_id,
                    "blueprint_name": "unknown",
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                    "work_items": [],
                }
            blueprint_name = plan_json.get("blueprint_name") or plan_json.get("blueprint") or "unknown"
            release_plan_payload = {
                "blueprint_id": plan_json.get("blueprint_id"),
                "target_kind": "blueprint",
                "target_fqn": blueprint_name,
                "name": f"Release plan for {blueprint_name}",
                "to_version": "0.1.0",
                "from_version": "",
                "milestones_json": {"work_items": plan_json.get("work_items", [])},
                "last_run_id": run_id,
            }
            release_plan = _post_json("/xyn/internal/release-plans/upsert", release_plan_payload)
            release_plan_id = release_plan.get("id")
            smoke_test = bool(plan_json.get("smoke_test"))
            steps = [
                {
                    "name": "prepare",
                    "commands": ["mkdir -p /var/lib/xyn/ems"],
                },
                {
                    "name": "deploy",
                    "commands": ["docker compose -f /var/lib/xyn/ems/docker-compose.yml up -d"],
                },
            ]
            if smoke_test:
                steps.append({"name": "smoke-test", "commands": ["uname -a"]})
            release_plan_json = {
                "release_plan_id": release_plan_id,
                "name": release_plan_payload["name"],
                "blueprint_id": plan_json.get("blueprint_id"),
                "blueprint": blueprint_name,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "tasks": plan_json.get("work_items", []),
                "steps": steps,
            }
            url_json = _write_artifact(run_id, "release_plan.json", json.dumps(release_plan_json, indent=2))
            md = (
                f"# Release Plan\n\n"
                f"- Blueprint: {release_plan_json.get('blueprint')}\n"
                f"- Generated: {release_plan_json.get('generated_at')}\n\n"
                "## Tasks\n"
            )
            for task_entry in release_plan_json.get("tasks", []):
                title = task_entry.get("title") or task_entry.get("id") or "work-item"
                task_type = task_entry.get("task_type") or task_entry.get("type") or "work-item"
                md += f"- {task_type}: {title}\n"
            url_md = _write_artifact(run_id, "release_plan.md", md)
            _post_json(
                f"/xyn/internal/runs/{run_id}/artifacts",
                {"name": "release_plan.json", "kind": "release_plan", "url": url_json},
            )
            _post_json(
                f"/xyn/internal/runs/{run_id}/artifacts",
                {"name": "release_plan.md", "kind": "release_plan", "url": url_md},
            )
            _post_json(
                "/xyn/internal/releases",
                {
                    "blueprint_id": plan_json.get("blueprint_id"),
                    "release_plan_id": release_plan_id,
                    "created_from_run_id": run_id,
                    "artifacts_json": [
                        {"name": "release_plan.json", "url": url_json},
                        {"name": "release_plan.md", "url": url_md},
                    ],
                },
            )
            _post_json(
                f"/xyn/internal/runs/{run_id}",
                {"status": "succeeded", "append_log": "Release plan generated.\n"},
            )
            _post_json(
                f"/xyn/internal/dev-tasks/{task_id}/complete",
                {"status": "succeeded"},
            )
            return

        if task_type == "deploy_release_plan":
            plan_json = None
            if source_run:
                plan_json = _download_artifact_json(source_run, input_artifact_key or "release_plan.json")
            if not plan_json and source_entity_type == "release_plan" and source_entity_id:
                release_plan = _get_json(f"/xyn/internal/release-plans/{source_entity_id}")
                last_run = release_plan.get("last_run")
                if last_run:
                    plan_json = _download_artifact_json(last_run, "release_plan.json")
            if not plan_json:
                raise RuntimeError("release_plan.json not found for deploy task")
            if not target_instance or not target_instance.get("instance_id"):
                raise RuntimeError("target instance missing for deploy task")
            plan_hash = _hash_release_plan(plan_json)
            deploy_state = _get_json(
                f"/xyn/internal/release-plans/{source_entity_id}/deploy-state?instance_id={target_instance.get('id')}"
            )
            state = deploy_state.get("state")
            if state and state.get("last_applied_hash") == plan_hash and not task.get("force"):
                deploy_execution = {
                    "status": "skipped_idempotent",
                    "target_instance_id": target_instance.get("id"),
                    "release_plan_hash": plan_hash,
                    "steps": [],
                }
                exec_url = _write_artifact(
                    run_id, "deploy_execution.json", json.dumps(deploy_execution, indent=2)
                )
                _post_json(
                    f"/xyn/internal/runs/{run_id}/artifacts",
                    {"name": "deploy_execution.json", "kind": "deploy", "url": exec_url},
                )
                _post_json(
                    f"/xyn/internal/runs/{run_id}",
                    {"status": "succeeded", "append_log": "Deploy skipped (already applied).\n"},
                )
                _post_json(
                    f"/xyn/internal/dev-tasks/{task_id}/complete",
                    {"status": "succeeded"},
                )
                return
            plan_body = json.dumps(plan_json, indent=2)
            plan_b64 = base64.b64encode(plan_body.encode("utf-8")).decode("utf-8")
            upload_commands = [
                "mkdir -p /var/lib/xyn",
                f"echo '{plan_b64}' | base64 -d > /var/lib/xyn/release_plan.json",
            ]
            _run_ssm_commands(
                target_instance.get("instance_id"),
                target_instance.get("aws_region"),
                upload_commands,
            )
            apply_result = _run_ssm_commands(
                target_instance.get("instance_id"),
                target_instance.get("aws_region"),
                ["xynctl apply --from /var/lib/xyn/release_plan.json"],
            )
            exec_result = _run_ssm_commands(
                target_instance.get("instance_id"),
                target_instance.get("aws_region"),
                ["cat /var/lib/xyn/deploy_execution.json"],
            )
            deploy_execution = {}
            try:
                deploy_execution = json.loads(exec_result.get("stdout", "") or "{}")
            except json.JSONDecodeError:
                deploy_execution = {
                    "status": "failed",
                    "error": "Failed to parse deploy_execution.json",
                    "stdout": exec_result.get("stdout", ""),
                    "stderr": exec_result.get("stderr", ""),
                }
            deploy_execution["release_plan_hash"] = plan_hash
            deploy_execution.setdefault("target_instance_id", target_instance.get("id"))
            command_records = []
            for step in deploy_execution.get("steps", []):
                for index, command in enumerate(step.get("commands", [])):
                    record = {
                        "step_name": step.get("name") or "step",
                        "command_index": index,
                        "shell": "sh",
                        "status": command.get("status"),
                        "exit_code": command.get("exit_code"),
                        "started_at": command.get("started_at"),
                        "finished_at": command.get("finished_at"),
                        "ssm_command_id": command.get("ssm_command_id", ""),
                        "stdout": command.get("stdout", ""),
                        "stderr": command.get("stderr", ""),
                    }
                    command_records.append(record)
                    _post_json(f"/xyn/internal/runs/{run_id}/commands", record)
            success = (
                apply_result.get("invocation_status") == "Success"
                and apply_result.get("response_code") == 0
                and deploy_execution.get("status") != "failed"
            )
            deploy_result = {
                "target_instance_id": target_instance.get("id"),
                "release_plan_hash": plan_hash,
                "apply": apply_result,
            }
            url = _write_artifact(run_id, "deploy_result.json", json.dumps(deploy_result, indent=2))
            exec_url = _write_artifact(run_id, "deploy_execution.json", json.dumps(deploy_execution, indent=2))
            _post_json(
                f"/xyn/internal/runs/{run_id}/artifacts",
                {"name": "deploy_result.json", "kind": "deploy", "url": url},
            )
            _post_json(
                f"/xyn/internal/runs/{run_id}/artifacts",
                {"name": "deploy_execution.json", "kind": "deploy", "url": exec_url},
            )
            _post_json(
                f"/xyn/internal/runs/{run_id}",
                {
                    "status": "succeeded" if success else "failed",
                    "append_log": "Deploy completed.\n",
                },
            )
            if success:
                _post_json(
                    f"/xyn/internal/release-plans/{source_entity_id}/deploy-state",
                    {
                        "instance_id": target_instance.get("id"),
                        "last_applied_hash": plan_hash,
                        "last_applied_at": datetime.utcnow().isoformat() + "Z",
                    },
                )
                instance_detail = _get_json(f"/xyn/internal/instances/{target_instance.get('id')}")
                _post_json(
                    f"/xyn/internal/instances/{target_instance.get('id')}/state",
                    {
                        "observed_release_id": instance_detail.get("desired_release_id"),
                        "observed_at": datetime.utcnow().isoformat() + "Z",
                        "last_deploy_run_id": run_id,
                        "health_status": "healthy",
                    },
                )
            else:
                _post_json(
                    f"/xyn/internal/instances/{target_instance.get('id')}/state",
                    {
                        "last_deploy_run_id": run_id,
                        "health_status": "failed",
                    },
                )
            _post_json(
                f"/xyn/internal/dev-tasks/{task_id}/complete",
                {"status": "succeeded" if success else "failed"},
            )
            return

        _post_json(
            f"/xyn/internal/runs/{run_id}",
            {"status": "succeeded", "append_log": "Dev task completed.\n"},
        )
        _post_json(
            f"/xyn/internal/dev-tasks/{task_id}/complete",
            {"status": "succeeded"},
        )
    except Exception as exc:
        try:
            _post_json(
                f"/xyn/internal/dev-tasks/{task_id}/complete",
                {"status": "failed", "error": str(exc)},
            )
            if run_id:
                _post_json(
                    f"/xyn/internal/runs/{run_id}",
                    {"status": "failed", "error": str(exc), "append_log": f"Dev task failed: {exc}\n"},
                )
        except Exception:
            pass
