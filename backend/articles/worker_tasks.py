import base64
import hashlib
import json
import os
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


def _load_schema(name: str) -> Dict[str, Any]:
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
    schema = _load_schema(_schema_for_kind(kind))
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
            payload = {
                "task_id": task_id,
                "task_type": "codegen",
                "status": "succeeded",
                "generated_at": datetime.utcnow().isoformat() + "Z",
            }
            url = _write_artifact(run_id, "codegen_result.json", json.dumps(payload, indent=2))
            _post_json(
                f"/xyn/internal/runs/{run_id}/artifacts",
                {"name": "codegen_result.json", "kind": "codegen", "url": url},
            )
            _post_json(
                f"/xyn/internal/runs/{run_id}",
                {"status": "succeeded", "append_log": "Codegen task completed.\n"},
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
                    "blueprint": "unknown",
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                    "tasks": [],
                }
        release_plan_payload = {
            "blueprint_id": plan_json.get("blueprint_id"),
            "target_kind": "blueprint",
            "target_fqn": plan_json.get("blueprint", ""),
            "name": f"Release plan for {plan_json.get('blueprint', 'blueprint')}",
            "to_version": "0.1.0",
            "from_version": "",
            "milestones_json": {"tasks": plan_json.get("tasks", [])},
            "last_run_id": run_id,
        }
        release_plan = _post_json("/xyn/internal/release-plans/upsert", release_plan_payload)
        release_plan_id = release_plan.get("id")
            release_plan_json = {
                "release_plan_id": release_plan_id,
                "name": release_plan_payload["name"],
                "blueprint_id": plan_json.get("blueprint_id"),
                "blueprint": plan_json.get("blueprint"),
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "tasks": plan_json.get("tasks", []),
                "steps": [
                    {
                        "name": "deploy",
                        "commands": ["uname -a"],
                    }
                ],
            }
        url_json = _write_artifact(run_id, "release_plan.json", json.dumps(release_plan_json, indent=2))
        md = (
            f"# Release Plan\n\n"
            f"- Blueprint: {release_plan_json.get('blueprint')}\n"
            f"- Generated: {release_plan_json.get('generated_at')}\n\n"
            "## Tasks\n"
        )
        for task_entry in release_plan_json.get("tasks", []):
            md += f"- {task_entry.get('task_type')}: {task_entry.get('title')}\n"
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
