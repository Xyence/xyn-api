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
CODEGEN_GIT_TOKEN = os.environ.get("XYENCE_CODEGEN_GIT_TOKEN", "").strip()
CODEGEN_COMMIT = os.environ.get("XYENCE_CODEGEN_COMMIT", "").strip() == "1"
CODEGEN_PUSH = os.environ.get("XYENCE_CODEGEN_PUSH", "").strip() == "1"


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


def _mark_noop_codegen(changes_made: bool, work_item_id: str, errors: List[Dict[str, Any]]) -> bool:
    if changes_made:
        return True
    errors.append(
        {
            "code": "no_changes",
            "message": "Codegen produced no patches or files.",
            "detail": {"work_item_id": work_item_id},
        }
    )
    return False


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
""",
        )
        _write_file(
            p("requirements.txt"),
            """fastapi==0.110.0
uvicorn==0.27.1
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
from ems_api.routes import health, devices, reports

app = FastAPI(title="EMS API")

app.include_router(health.router)
app.include_router(devices.router)
app.include_router(reports.router)
""",
        )
        _write_file(
            p("ems_api/routes/__init__.py"),
            "",
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
            p("ems_api/routes/devices.py"),
            """from fastapi import APIRouter

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("")
def list_devices():
    return []
""",
        )
        _write_file(
            p("ems_api/routes/reports.py"),
            """from fastapi import APIRouter

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("")
def list_reports():
    return []
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
                "pyproject.toml",
                "ems_api/__init__.py",
                "ems_api/main.py",
                "ems_api/routes/__init__.py",
                "ems_api/routes/health.py",
                "ems_api/routes/devices.py",
                "ems_api/routes/reports.py",
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
            """from fastapi import APIRouter

router = APIRouter(prefix="/devices")

@router.get("/")
def list_devices():
    return []

@router.post("/")
def create_device():
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
            """from fastapi import APIRouter

router = APIRouter(prefix="/reports")

@router.get("/")
def get_reports():
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
            """import { Link } from "react-router-dom";

export default function Login() {
  return (
    <main>
      <h1>Login (OIDC stub)</h1>
      <p>This is a placeholder login view.</p>
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
            workspace_root = os.path.join(CODEGEN_WORKDIR, task_id)
            os.system(f"rm -rf {workspace_root}")
            os.makedirs(workspace_root, exist_ok=True)
            repo_results = []
            artifacts = []
            errors = []
            success = True
            changes_made = False
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
                commit_info = None
                if diff.strip() and CODEGEN_COMMIT:
                    branch = f"codegen/{task_id}"
                    _git_cmd(repo_dir, f"git checkout -b {branch}")
                    _git_cmd(repo_dir, f"git commit -am \"codegen: {work_item_id}\"")
                    sha = os.popen(f"cd {repo_dir} && git rev-parse HEAD").read().strip()
                    pushed = False
                    if CODEGEN_PUSH:
                        _git_cmd(repo_dir, f"git push -u origin {branch}")
                        pushed = True
                    commit_info = {
                        "sha": sha,
                        "message": f"codegen: {work_item_id}",
                        "branch": branch,
                        "pushed": pushed,
                    }
                repo_results.append(
                    {
                        "repo": {
                            "name": repo.get("name"),
                            "url": repo.get("url"),
                            "ref": repo.get("ref"),
                            "path_root": repo.get("path_root"),
                        },
                        "files_changed": files_changed,
                        "patches": patches,
                        "commands_executed": commands_executed,
                        "commit": commit_info,
                    }
                )
            success = success and _mark_noop_codegen(changes_made, work_item_id, errors)
            result = {
                "schema_version": "codegen_result.v1",
                "task_id": task_id,
                "work_item_id": work_item_id,
                "blueprint_id": plan_json.get("blueprint_id"),
                "summary": {
                    "outcome": "succeeded" if success else "failed",
                    "changes": f"{len(repo_results)} repo(s) updated" if success else "No changes",
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
