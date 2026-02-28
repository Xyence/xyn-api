import copy
import hashlib
import io
import json
import os
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from django.db import connection, transaction
from django.utils import timezone as dj_timezone

from .models import (
    Artifact,
    ArtifactBindingValue,
    ArtifactInstallReceipt,
    ArtifactPackage,
    ArtifactRevision,
    ArtifactType,
    PlatformConfigDocument,
    Workspace,
)

MANIFEST_FORMAT_VERSION = 1
PACKAGE_STORAGE_ROOT = Path(os.environ.get("XYN_ARTIFACT_PACKAGE_ROOT") or "/tmp/xyn-artifact-packages")
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ALLOWED_ARTIFACT_TYPES = {
    "article",
    "workflow",
    "app_shell",
    "auth_login",
    "data_model",
    "ui_view",
    "integration",
    "context_pack",
    "blueprint",
    "module",
}


class ArtifactPackageError(Exception):
    pass


class ArtifactPackageValidationError(ArtifactPackageError):
    def __init__(self, errors: List[str]):
        super().__init__("invalid package")
        self.errors = errors


class ArtifactPackageInstallError(ArtifactPackageError):
    def __init__(self, errors: List[str]):
        super().__init__("install failed")
        self.errors = errors


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_semver(value: str) -> Optional[Tuple[int, int, int]]:
    raw = str(value or "").strip()
    if not SEMVER_RE.match(raw):
        return None
    core = raw.split("-", 1)[0].split("+", 1)[0]
    major, minor, patch = core.split(".")
    return int(major), int(minor), int(patch)


def _matches_version_range(version: str, version_range: str) -> bool:
    if not version_range:
        return True
    parsed = _parse_semver(version)
    if not parsed:
        return False
    if version_range.startswith("^"):
        base = _parse_semver(version_range[1:])
        if not base:
            return False
        major, minor, patch = parsed
        b_major, b_minor, b_patch = base
        if major != b_major:
            return False
        return (minor, patch) >= (b_minor, b_patch)
    return version == version_range


def _workspace_for_artifacts() -> Workspace:
    workspace = Workspace.objects.filter(slug="platform-builder").first()
    if workspace:
        return workspace
    workspace, _ = Workspace.objects.get_or_create(
        slug="artifact-library",
        defaults={"name": "Artifact Library", "description": "Portable application artifacts"},
    )
    return workspace


def _latest_content(artifact: Artifact) -> Dict[str, Any]:
    latest = ArtifactRevision.objects.filter(artifact=artifact).order_by("-revision_number").first()
    if latest and isinstance(latest.content_json, dict):
        return latest.content_json
    return {}


def _manifest_artifact_ref(item: Dict[str, Any]) -> str:
    return f"{item.get('type')}:{item.get('slug')}@{item.get('version')}"


def _artifact_paths(item: Dict[str, Any]) -> Tuple[str, str]:
    base = f"artifacts/{item['type']}/{item['slug']}/{item['version']}"
    return f"{base}/artifact.json", f"{base}/payload/payload.json"


def _validate_manifest(manifest: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if int(manifest.get("format_version") or 0) != MANIFEST_FORMAT_VERSION:
        errors.append("manifest.format_version must be 1")
    package_name = str(manifest.get("package_name") or "").strip()
    if not package_name:
        errors.append("manifest.package_name is required")
    package_version = str(manifest.get("package_version") or "").strip()
    if not _parse_semver(package_version):
        errors.append("manifest.package_version must be semver")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("manifest.artifacts must be a non-empty array")
        return errors

    seen: set[str] = set()
    for idx, entry in enumerate(artifacts):
        if not isinstance(entry, dict):
            errors.append(f"manifest.artifacts[{idx}] must be an object")
            continue
        a_type = str(entry.get("type") or "").strip()
        slug = str(entry.get("slug") or "").strip()
        version = str(entry.get("version") or "").strip()
        if a_type not in ALLOWED_ARTIFACT_TYPES:
            errors.append(f"manifest.artifacts[{idx}].type is unsupported")
        if not slug:
            errors.append(f"manifest.artifacts[{idx}].slug is required")
        if not _parse_semver(version):
            errors.append(f"manifest.artifacts[{idx}].version must be semver")
        ref = f"{a_type}:{slug}@{version}"
        if ref in seen:
            errors.append(f"manifest.artifacts[{idx}] duplicate identity {ref}")
        seen.add(ref)

    checksums = manifest.get("checksums")
    if not isinstance(checksums, dict) or not checksums:
        errors.append("manifest.checksums must be a non-empty object")
    return errors


def _read_zip_to_map(blob: bytes) -> Dict[str, bytes]:
    files: Dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(blob), "r") as archive:
            for name in archive.namelist():
                normalized = str(name or "").strip().lstrip("/")
                if not normalized or normalized.endswith("/"):
                    continue
                if ".." in Path(normalized).parts:
                    raise ArtifactPackageValidationError([f"invalid path in zip: {normalized}"])
                files[normalized] = archive.read(name)
    except ArtifactPackageValidationError:
        raise
    except Exception as exc:
        raise ArtifactPackageValidationError([f"invalid zip: {exc.__class__.__name__}"])
    return files


def _verify_checksums(manifest: Dict[str, Any], file_map: Dict[str, bytes]) -> List[str]:
    errors: List[str] = []
    checksums = manifest.get("checksums") if isinstance(manifest.get("checksums"), dict) else {}
    for path, expected in checksums.items():
        raw = file_map.get(path)
        if raw is None:
            errors.append(f"missing file listed in checksums: {path}")
            continue
        actual = _sha256_bytes(raw)
        if str(expected or "") != actual:
            errors.append(f"checksum mismatch: {path}")
    return errors


def _parse_package_blob(blob: bytes) -> Tuple[Dict[str, Any], Dict[str, bytes], str]:
    file_map = _read_zip_to_map(blob)
    if "manifest.json" not in file_map:
        raise ArtifactPackageValidationError(["manifest.json not found in package"])
    try:
        manifest = json.loads(file_map["manifest.json"].decode("utf-8"))
    except Exception:
        raise ArtifactPackageValidationError(["manifest.json is not valid JSON"])
    if not isinstance(manifest, dict):
        raise ArtifactPackageValidationError(["manifest.json root must be an object"])

    errors = _validate_manifest(manifest)
    errors.extend(_verify_checksums(manifest, file_map))
    if errors:
        raise ArtifactPackageValidationError(errors)
    return manifest, file_map, _sha256_bytes(blob)


def import_package_blob(*, blob: bytes, created_by=None) -> ArtifactPackage:
    manifest, _file_map, package_hash = _parse_package_blob(blob)
    PACKAGE_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
    package = ArtifactPackage.objects.create(
        name=str(manifest.get("package_name") or "").strip(),
        version=str(manifest.get("package_version") or "").strip(),
        manifest=manifest,
        package_hash=package_hash,
        created_by=created_by,
    )
    blob_path = PACKAGE_STORAGE_ROOT / f"{package.id}.zip"
    blob_path.write_bytes(blob)
    package.file_blob_ref = str(blob_path)
    package.save(update_fields=["file_blob_ref"])
    return package


def _binding_value_from_registry(binding: Dict[str, Any]) -> Optional[Any]:
    name = str(binding.get("name") or "").strip()
    if not name:
        return None
    row = ArtifactBindingValue.objects.filter(name=name).first()
    if not row:
        return None
    if row.binding_type == "secret_ref":
        return row.secret_ref.external_ref if row.secret_ref_id and row.secret_ref else None
    return row.value


def resolve_bindings(
    required_bindings: List[Dict[str, Any]],
    *,
    overrides: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    resolved: Dict[str, Any] = {}
    errors: List[str] = []
    overrides = overrides or {}

    for binding in required_bindings:
        name = str(binding.get("name") or "").strip()
        if not name:
            continue
        required = bool(binding.get("required", False))
        strategy = str(binding.get("resolution_strategy") or "instance_setting").strip() or "instance_setting"

        value = overrides.get(name)
        if value is None and strategy in {"instance_setting", "prompt_user"}:
            value = _binding_value_from_registry(binding)
        if value is None and strategy == "environment":
            value = os.environ.get(name)
        if value is None:
            value = binding.get("default_value")

        if value is None and required:
            errors.append(f"binding unresolved: {name}")
            continue
        resolved[name] = value
    return resolved, errors


def _artifact_index(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    return {_manifest_artifact_ref(row): row for row in rows if isinstance(row, dict)}


def _load_package(package: ArtifactPackage) -> Tuple[Dict[str, Any], Dict[str, bytes]]:
    path = Path(str(package.file_blob_ref or "").strip())
    if not path.exists():
        raise ArtifactPackageValidationError(["package blob is missing on disk"])
    blob = path.read_bytes()
    manifest, files, _hash = _parse_package_blob(blob)
    return manifest, files


def _dependency_errors(manifest: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    included = _artifact_index(manifest)
    for item in manifest.get("artifacts") or []:
        if not isinstance(item, dict):
            continue
        deps = item.get("dependencies") if isinstance(item.get("dependencies"), list) else []
        for dep in deps:
            if not isinstance(dep, dict):
                errors.append(f"invalid dependency in {_manifest_artifact_ref(item)}")
                continue
            dep_type = str(dep.get("type") or "").strip()
            dep_slug = str(dep.get("slug") or "").strip()
            dep_range = str(dep.get("version_range") or "").strip()
            if not dep_type or not dep_slug:
                errors.append(f"invalid dependency in {_manifest_artifact_ref(item)}")
                continue

            found_included = False
            for key, candidate in included.items():
                _ = key
                if str(candidate.get("type") or "") != dep_type:
                    continue
                if str(candidate.get("slug") or "") != dep_slug:
                    continue
                if _matches_version_range(str(candidate.get("version") or ""), dep_range):
                    found_included = True
                    break
            if found_included:
                continue

            installed = Artifact.objects.filter(type__slug=dep_type, slug=dep_slug).order_by("-updated_at")
            installed_ok = any(_matches_version_range(str(row.package_version or ""), dep_range) for row in installed)
            if not installed_ok:
                errors.append(
                    f"dependency unresolved for {_manifest_artifact_ref(item)}: {dep_type}:{dep_slug} {dep_range or '*'}"
                )
    return errors


def _collect_bindings(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for item in manifest.get("artifacts") or []:
        if not isinstance(item, dict):
            continue
        bindings = item.get("bindings") if isinstance(item.get("bindings"), list) else []
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            name = str(binding.get("name") or "").strip()
            if not name:
                continue
            merged[name] = binding
    return list(merged.values())


def _topological_sort(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = [item for item in (manifest.get("artifacts") or []) if isinstance(item, dict)]
    by_ref = {_manifest_artifact_ref(item): item for item in items}
    incoming: Dict[str, int] = {key: 0 for key in by_ref.keys()}
    edges: Dict[str, List[str]] = {key: [] for key in by_ref.keys()}

    for ref, item in by_ref.items():
        deps = item.get("dependencies") if isinstance(item.get("dependencies"), list) else []
        for dep in deps:
            if not isinstance(dep, dict):
                continue
            dep_type = str(dep.get("type") or "").strip()
            dep_slug = str(dep.get("slug") or "").strip()
            dep_range = str(dep.get("version_range") or "").strip()
            match_ref = None
            for candidate_ref, candidate in by_ref.items():
                if str(candidate.get("type") or "") != dep_type:
                    continue
                if str(candidate.get("slug") or "") != dep_slug:
                    continue
                if _matches_version_range(str(candidate.get("version") or ""), dep_range):
                    match_ref = candidate_ref
                    break
            if match_ref:
                edges[match_ref].append(ref)
                incoming[ref] += 1

    queue = sorted([ref for ref, count in incoming.items() if count == 0])
    ordered: List[str] = []
    while queue:
        current = queue.pop(0)
        ordered.append(current)
        for nxt in edges[current]:
            incoming[nxt] -= 1
            if incoming[nxt] == 0:
                queue.append(nxt)
                queue.sort()

    if len(ordered) != len(by_ref):
        raise ArtifactPackageInstallError(["dependency cycle detected in package"])
    return [by_ref[ref] for ref in ordered]


def _ensure_artifact_type(slug: str) -> ArtifactType:
    artifact_type, _ = ArtifactType.objects.get_or_create(
        slug=slug,
        defaults={"name": slug.replace("_", " ").title(), "description": "Application artifact", "icon": "Package"},
    )
    return artifact_type


def _upsert_platform_config(section: str, key: str, value: Dict[str, Any], *, user=None) -> None:
    latest = PlatformConfigDocument.objects.order_by("-created_at", "-version").first()
    current = copy.deepcopy(latest.config_json if latest and isinstance(latest.config_json, dict) else {})
    if section not in current or not isinstance(current.get(section), dict):
        current[section] = {}
    existing = current[section].get(key)
    if existing == value:
        return
    current[section][key] = value
    next_version = int(latest.version if latest else 0) + 1
    PlatformConfigDocument.objects.create(
        version=next_version,
        config_json=current,
        created_by=user if getattr(user, "is_authenticated", False) else None,
    )


def _apply_data_model_hook(*, slug: str, content: Dict[str, Any]) -> Dict[str, Any]:
    schema = content.get("schema") if isinstance(content.get("schema"), dict) else {}
    table_name = str(schema.get("table_name") or slug).strip().lower()
    if not IDENT_RE.match(table_name):
        raise ArtifactPackageInstallError([f"invalid data_model table_name: {table_name}"])
    columns = schema.get("columns") if isinstance(schema.get("columns"), list) else []
    if not columns:
        columns = [{"name": "id", "type": "text", "nullable": False}]

    sql_cols = []
    for col in columns:
        if not isinstance(col, dict):
            continue
        name = str(col.get("name") or "").strip().lower()
        ctype = str(col.get("type") or "text").strip().lower()
        nullable = bool(col.get("nullable", True))
        if not IDENT_RE.match(name):
            raise ArtifactPackageInstallError([f"invalid data_model column name: {name}"])
        if ctype in {"uuid"}:
            sql_type = "uuid"
        elif ctype in {"int", "integer"}:
            sql_type = "integer"
        elif ctype in {"bool", "boolean"}:
            sql_type = "boolean"
        elif ctype in {"json", "jsonb"}:
            sql_type = "jsonb"
        elif ctype in {"timestamp", "timestamptz", "datetime"}:
            sql_type = "timestamptz"
        else:
            sql_type = "text"
        not_null = " NOT NULL" if not nullable else ""
        sql_cols.append(f'"{name}" {sql_type}{not_null}')
    if not any(col.startswith('"id"') for col in sql_cols):
        sql_cols.insert(0, '"id" text NOT NULL')

    sql = f'CREATE TABLE IF NOT EXISTS "{table_name}" ({", ".join(sql_cols)});'
    with connection.cursor() as cursor:
        cursor.execute(sql)
    return {"table_name": table_name, "columns": len(sql_cols)}


def _run_install_hook(*, artifact_type: str, slug: str, content: Dict[str, Any], user=None) -> Dict[str, Any]:
    if artifact_type == "data_model":
        return _apply_data_model_hook(slug=slug, content=content)
    if artifact_type == "app_shell":
        _upsert_platform_config("app_shell_registry", slug, content, user=user)
        return {"registered": True, "section": "app_shell_registry"}
    if artifact_type == "auth_login":
        _upsert_platform_config("auth_login_registry", slug, content, user=user)
        return {"registered": True, "section": "auth_login_registry"}
    if artifact_type == "ui_view":
        _upsert_platform_config("ui_view_registry", slug, content, user=user)
        return {"registered": True, "section": "ui_view_registry"}
    if artifact_type == "workflow":
        _upsert_platform_config("workflow_registry", slug, content, user=user)
        return {"registered": True, "section": "workflow_registry"}
    return {"registered": False}


def validate_package_install(
    package: ArtifactPackage,
    *,
    binding_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    manifest, _files = _load_package(package)
    errors = _dependency_errors(manifest)
    bindings = _collect_bindings(manifest)
    resolved_bindings, binding_errors = resolve_bindings(bindings, overrides=binding_overrides)
    errors.extend(binding_errors)

    ordered: List[Dict[str, Any]] = []
    if not errors:
        ordered = _topological_sort(manifest)

    planned_changes: List[Dict[str, Any]] = []
    for item in ordered:
        current = Artifact.objects.filter(type__slug=item["type"], slug=item["slug"]).first()
        if not current:
            action = "install"
        elif str(current.package_version or "") == str(item.get("version") or ""):
            action = "reinstall"
        else:
            action = "upgrade"
        planned_changes.append(
            {
                "type": item["type"],
                "slug": item["slug"],
                "from_version": str(current.package_version or "") if current else None,
                "to_version": str(item.get("version") or ""),
                "action": action,
            }
        )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "package": {
            "name": str(manifest.get("package_name") or ""),
            "version": str(manifest.get("package_version") or ""),
            "format_version": int(manifest.get("format_version") or 0),
        },
        "dependency_plan": [
            {
                "type": item.get("type"),
                "slug": item.get("slug"),
                "version": item.get("version"),
            }
            for item in ordered
        ],
        "required_bindings": bindings,
        "resolved_bindings": resolved_bindings,
        "planned_changes": planned_changes,
    }


def install_package(
    package: ArtifactPackage,
    *,
    binding_overrides: Optional[Dict[str, Any]] = None,
    installed_by=None,
) -> ArtifactInstallReceipt:
    manifest, files = _load_package(package)
    validation = validate_package_install(package, binding_overrides=binding_overrides)

    operations: List[Dict[str, Any]] = []
    operations.append({"step": "validate", "at": _now_iso(), "result": "success" if validation["valid"] else "failed"})
    if not validation["valid"]:
        receipt = ArtifactInstallReceipt.objects.create(
            package=package,
            package_name=package.name,
            package_version=package.version,
            package_hash=package.package_hash,
            installed_by=installed_by if getattr(installed_by, "is_authenticated", False) else None,
            install_mode="install",
            resolved_bindings=validation.get("resolved_bindings") or {},
            operations=operations,
            status="failed",
            error_summary="; ".join(validation["errors"]),
            artifact_changes=[],
        )
        return receipt

    resolved_bindings = validation.get("resolved_bindings") or {}
    ordered = _topological_sort(manifest)
    workspace = _workspace_for_artifacts()
    artifact_changes: List[Dict[str, Any]] = []
    install_mode = "install"

    try:
        with transaction.atomic():
            for item in ordered:
                artifact_json_path, payload_path = _artifact_paths(item)
                raw = files.get(artifact_json_path)
                if raw is None:
                    raise ArtifactPackageInstallError([f"artifact file missing: {artifact_json_path}"])
                payload_raw = files.get(payload_path, b"{}")
                try:
                    artifact_json = json.loads(raw.decode("utf-8"))
                except Exception:
                    raise ArtifactPackageInstallError([f"invalid json in {artifact_json_path}"])
                try:
                    payload_json = json.loads(payload_raw.decode("utf-8"))
                except Exception:
                    payload_json = {}

                item_type = str(item.get("type") or "")
                item_slug = str(item.get("slug") or "")
                item_version = str(item.get("version") or "")
                item_hash = str(item.get("artifact_hash") or _sha256_bytes(raw))
                dependencies = item.get("dependencies") if isinstance(item.get("dependencies"), list) else []
                bindings = item.get("bindings") if isinstance(item.get("bindings"), list) else []
                content_obj = artifact_json.get("content") if isinstance(artifact_json.get("content"), dict) else {}
                if not content_obj and isinstance(payload_json, dict):
                    content_obj = payload_json

                type_row = _ensure_artifact_type(item_type)
                existing = Artifact.objects.filter(type=type_row, slug=item_slug).first()
                if existing and str(existing.package_version or "") == item_version and str(existing.content_hash or "") == item_hash:
                    operations.append(
                        {
                            "step": "install_artifact",
                            "artifact": f"{item_type}:{item_slug}@{item_version}",
                            "at": _now_iso(),
                            "result": "skipped",
                            "reason": "identical",
                        }
                    )
                    artifact_changes.append(
                        {
                            "artifact_id": str(existing.id),
                            "type": item_type,
                            "slug": item_slug,
                            "from_version": item_version,
                            "to_version": item_version,
                            "action": "skip",
                        }
                    )
                    continue

                action = "install"
                if existing:
                    action = "upgrade" if str(existing.package_version or "") != item_version else "reinstall"
                    if action == "upgrade":
                        install_mode = "upgrade"
                    elif install_mode != "upgrade":
                        install_mode = "reinstall"

                    existing.title = str(item.get("title") or existing.title or item_slug)
                    existing.summary = str(item.get("description") or existing.summary or "")
                    existing.package_version = item_version
                    existing.schema_version = str(artifact_json.get("schema_version") or existing.schema_version or "app.v1")
                    existing.content_ref = {
                        "package_id": str(package.id),
                        "artifact_path": artifact_json_path,
                        "payload_path": payload_path,
                    }
                    existing.dependencies = dependencies
                    existing.bindings = bindings
                    existing.status = "active"
                    existing.content_hash = item_hash
                    existing.artifact_state = "canonical"
                    existing.save(
                        update_fields=[
                            "title",
                            "summary",
                            "package_version",
                            "schema_version",
                            "content_ref",
                            "dependencies",
                            "bindings",
                            "status",
                            "content_hash",
                            "artifact_state",
                            "updated_at",
                        ]
                    )
                    artifact = existing
                else:
                    artifact = Artifact.objects.create(
                        workspace=workspace,
                        type=type_row,
                        title=str(item.get("title") or item_slug),
                        summary=str(item.get("description") or ""),
                        slug=item_slug,
                        package_version=item_version,
                        schema_version=str(artifact_json.get("schema_version") or "app.v1"),
                        content_ref={
                            "package_id": str(package.id),
                            "artifact_path": artifact_json_path,
                            "payload_path": payload_path,
                        },
                        dependencies=dependencies,
                        bindings=bindings,
                        status="active",
                        artifact_state="canonical",
                        content_hash=item_hash,
                        source_ref_type="ArtifactPackage",
                        source_ref_id=str(package.id),
                        visibility="private",
                    )

                next_rev = (
                    ArtifactRevision.objects.filter(artifact=artifact)
                    .order_by("-revision_number")
                    .values_list("revision_number", flat=True)
                    .first()
                )
                ArtifactRevision.objects.create(
                    artifact=artifact,
                    revision_number=int(next_rev or 0) + 1,
                    content_json={
                        "content": content_obj,
                        "resolved_bindings": resolved_bindings,
                        "manifest_ref": {
                            "package_name": package.name,
                            "package_version": package.version,
                            "artifact": _manifest_artifact_ref(item),
                        },
                    },
                    created_by=None,
                )

                hook_result = _run_install_hook(
                    artifact_type=item_type,
                    slug=item_slug,
                    content=content_obj if isinstance(content_obj, dict) else {},
                    user=installed_by,
                )

                operations.append(
                    {
                        "step": "install_artifact",
                        "artifact": f"{item_type}:{item_slug}@{item_version}",
                        "at": _now_iso(),
                        "result": "success",
                        "action": action,
                        "hook": hook_result,
                    }
                )
                artifact_changes.append(
                    {
                        "artifact_id": str(artifact.id),
                        "type": item_type,
                        "slug": item_slug,
                        "from_version": str(existing.package_version or "") if existing and action != "install" else None,
                        "to_version": item_version,
                        "action": action,
                    }
                )

            receipt = ArtifactInstallReceipt.objects.create(
                package=package,
                package_name=package.name,
                package_version=package.version,
                package_hash=package.package_hash,
                installed_by=installed_by if getattr(installed_by, "is_authenticated", False) else None,
                install_mode=install_mode,
                resolved_bindings=resolved_bindings,
                operations=operations,
                status="success",
                error_summary="",
                artifact_changes=artifact_changes,
            )
            return receipt
    except ArtifactPackageInstallError as exc:
        operations.append({"step": "install", "at": _now_iso(), "result": "failed", "error": "; ".join(exc.errors)})
        return ArtifactInstallReceipt.objects.create(
            package=package,
            package_name=package.name,
            package_version=package.version,
            package_hash=package.package_hash,
            installed_by=installed_by if getattr(installed_by, "is_authenticated", False) else None,
            install_mode=install_mode,
            resolved_bindings=validation.get("resolved_bindings") or {},
            operations=operations,
            status="failed",
            error_summary="; ".join(exc.errors),
            artifact_changes=artifact_changes,
        )


def export_artifact_package(*, root_artifact: Artifact, package_name: str, package_version: str) -> bytes:
    if not _parse_semver(package_version):
        raise ArtifactPackageValidationError(["package_version must be semver"])

    included: Dict[str, Artifact] = {}
    stack: List[Artifact] = [root_artifact]
    while stack:
        current = stack.pop()
        key = f"{current.type.slug}:{current.slug}"
        if key in included:
            continue
        included[key] = current
        deps = current.dependencies if isinstance(current.dependencies, list) else []
        for dep in deps:
            if not isinstance(dep, dict):
                continue
            dep_type = str(dep.get("type") or "").strip()
            dep_slug = str(dep.get("slug") or "").strip()
            dep_range = str(dep.get("version_range") or "").strip()
            candidate = Artifact.objects.filter(type__slug=dep_type, slug=dep_slug).order_by("-updated_at").first()
            if not candidate:
                continue
            if dep_range and not _matches_version_range(str(candidate.package_version or ""), dep_range):
                continue
            stack.append(candidate)

    files: Dict[str, bytes] = {}
    manifest_artifacts: List[Dict[str, Any]] = []
    for artifact in sorted(included.values(), key=lambda row: (row.type.slug, row.slug)):
        artifact_version = str(artifact.package_version or "0.1.0").strip() or "0.1.0"
        if not _parse_semver(artifact_version):
            artifact_version = "0.1.0"
        content = _latest_content(artifact)
        entry = {
            "type": artifact.type.slug,
            "slug": artifact.slug,
            "version": artifact_version,
            "artifact_id": str(artifact.id),
            "artifact_hash": str(artifact.content_hash or ""),
            "dependencies": artifact.dependencies if isinstance(artifact.dependencies, list) else [],
            "bindings": artifact.bindings if isinstance(artifact.bindings, list) else [],
            "title": artifact.title,
            "description": artifact.summary or "",
        }
        manifest_artifacts.append(entry)

        artifact_path, payload_path = _artifact_paths(entry)
        artifact_payload = {
            "artifact": {
                "type": entry["type"],
                "slug": entry["slug"],
                "version": entry["version"],
                "artifact_id": entry["artifact_id"],
                "title": entry["title"],
                "description": entry["description"],
                "schema_version": artifact.schema_version,
                "dependencies": entry["dependencies"],
                "bindings": entry["bindings"],
            },
            "content": content.get("content") if isinstance(content.get("content"), dict) else content,
            "metadata": {
                "exported_at": _now_iso(),
                "content_ref": artifact.content_ref if isinstance(artifact.content_ref, dict) else {},
            },
        }
        raw_artifact = json.dumps(artifact_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        raw_payload = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        files[artifact_path] = raw_artifact
        files[payload_path] = raw_payload
        entry["artifact_hash"] = _sha256_bytes(raw_artifact)

    manifest = {
        "format_version": MANIFEST_FORMAT_VERSION,
        "package_name": package_name,
        "package_version": package_version,
        "built_at": _now_iso(),
        "platform_compatibility": {
            "min_version": "1.0.0",
            "max_version_optional": None,
            "required_features": ["artifact_packages_v1"],
        },
        "artifacts": manifest_artifacts,
        "entrypoints": [{"type": root_artifact.type.slug, "slug": root_artifact.slug}],
    }

    checksums = {
        path: _sha256_bytes(content)
        for path, content in files.items()
    }
    manifest["checksums"] = checksums
    files["manifest.json"] = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    blob = io.BytesIO()
    with zipfile.ZipFile(blob, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files.keys()):
            archive.writestr(path, files[path])
    return blob.getvalue()
