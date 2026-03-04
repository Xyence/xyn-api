from __future__ import annotations

import hashlib
import os
import shlex
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Tuple

import yaml


@dataclass
class PreparedPlan:
    compose_project: str
    remote_workdir: str
    compose_file_path: str
    compose_yaml: str
    ssh: Dict[str, Any]
    ui_port: int
    api_port: int
    ems_port: Optional[int]
    components: List[Dict[str, Any]]
    fqdn: str
    scheme: str


@dataclass
class DriverResult:
    status: str
    stdout: str
    stderr: str
    details: Dict[str, Any]


@dataclass
class HealthResult:
    status: str
    checks: Dict[str, Any]


class InstanceDriver(Protocol):
    def prepare(self, *, instance: Dict[str, Any], release_spec: Dict[str, Any]) -> PreparedPlan:
        ...

    def apply(self, prepared_plan: PreparedPlan) -> DriverResult:
        ...

    def check_health(self, driver_result: DriverResult, release_spec: Dict[str, Any]) -> HealthResult:
        ...


@dataclass
class SshRunResult:
    command: str
    returncode: int
    stdout: str
    stderr: str


class SshExecutionError(RuntimeError):
    pass


class SshExecutor:
    def __init__(
        self,
        *,
        host: str,
        user: str,
        port: int = 22,
        private_key: str,
        strict_host_key_checking: bool = False,
        known_hosts: str = "",
        connect_timeout_seconds: int = 20,
    ) -> None:
        self.host = host
        self.user = user
        self.port = int(port or 22)
        self.private_key = private_key
        self.strict_host_key_checking = bool(strict_host_key_checking)
        self.known_hosts = known_hosts
        self.connect_timeout_seconds = int(connect_timeout_seconds or 20)
        self._tmpdir = tempfile.TemporaryDirectory(prefix="xyn-ssh-")
        self._key_path = Path(self._tmpdir.name) / "id_rsa"
        self._known_hosts_path = Path(self._tmpdir.name) / "known_hosts"
        self._key_path.write_text(self.private_key, encoding="utf-8")
        os.chmod(self._key_path, 0o600)
        if self.known_hosts:
            self._known_hosts_path.write_text(self.known_hosts, encoding="utf-8")
        else:
            self._known_hosts_path.write_text("", encoding="utf-8")

    def close(self) -> None:
        self._tmpdir.cleanup()

    def __enter__(self) -> "SshExecutor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _ssh_base(self) -> List[str]:
        args = [
            "ssh",
            "-i",
            str(self._key_path),
            "-p",
            str(self.port),
            "-o",
            f"ConnectTimeout={self.connect_timeout_seconds}",
            "-o",
            "ServerAliveInterval=20",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            f"UserKnownHostsFile={self._known_hosts_path}",
            "-o",
            "StrictHostKeyChecking=yes" if self.strict_host_key_checking else "StrictHostKeyChecking=no",
        ]
        return args

    def run(self, command: str, *, timeout_seconds: int = 120, check: bool = True) -> SshRunResult:
        target = f"{self.user}@{self.host}"
        full = self._ssh_base() + [target, command]
        proc = subprocess.run(full, capture_output=True, text=True, timeout=timeout_seconds)
        result = SshRunResult(command=command, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        if check and proc.returncode != 0:
            raise SshExecutionError(f"SSH command failed ({proc.returncode}): {command}\n{proc.stderr}")
        return result

    def upload_text(self, *, remote_path: str, content: str, timeout_seconds: int = 120) -> None:
        remote_dir = str(Path(remote_path).parent)
        self.run(f"mkdir -p {shlex.quote(remote_dir)}", timeout_seconds=timeout_seconds)
        local_file = Path(self._tmpdir.name) / f"upload-{uuid.uuid4().hex}.tmp"
        local_file.write_text(content, encoding="utf-8")
        target = f"{self.user}@{self.host}:{remote_path}"
        scp_cmd = [
            "scp",
            "-i",
            str(self._key_path),
            "-P",
            str(self.port),
            "-o",
            f"ConnectTimeout={self.connect_timeout_seconds}",
            "-o",
            f"UserKnownHostsFile={self._known_hosts_path}",
            "-o",
            "StrictHostKeyChecking=yes" if self.strict_host_key_checking else "StrictHostKeyChecking=no",
            str(local_file),
            target,
        ]
        proc = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=timeout_seconds)
        if proc.returncode != 0:
            raise SshExecutionError(f"SCP upload failed ({proc.returncode}): {proc.stderr}")


def _deterministic_short_id(seed: str) -> str:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return digest[:8]


def _parse_listening_ports(raw: str) -> List[int]:
    ports: List[int] = []
    for line in str(raw or "").splitlines():
        token = str(line or "").strip()
        if not token:
            continue
        try:
            value = int(token)
        except ValueError:
            continue
        if 1 <= value <= 65535:
            ports.append(value)
    return sorted(set(ports))


def allocate_remote_ports(used_ports: List[int], *, requested_ui: Optional[int], requested_api: Optional[int], start: int = 42000, end: int = 42999) -> Tuple[int, int]:
    used = set(int(p) for p in used_ports)
    if requested_ui and requested_api:
        if requested_ui in used or requested_api in used:
            raise RuntimeError("Requested ui/api ports are already in use on target host")
        return int(requested_ui), int(requested_api)

    selected: List[int] = []
    for candidate in range(start, end + 1):
        if candidate in used:
            continue
        selected.append(candidate)
        if len(selected) >= 2:
            break
    if len(selected) < 2:
        raise RuntimeError("Unable to allocate free ports on target host")
    ui = int(requested_ui) if requested_ui else selected[0]
    api = int(requested_api) if requested_api else (selected[1] if selected[0] == ui else selected[0])
    if api == ui:
        api = selected[1]
    return ui, api


def compute_base_urls(*, fqdn: str, scheme: str, public_hostname: str, public_ipv4: str, ui_port: int, api_port: int) -> Dict[str, str]:
    clean_fqdn = str(fqdn or "").strip().rstrip(".")
    clean_scheme = str(scheme or "http").strip().lower() or "http"
    if clean_fqdn:
        base = f"{clean_scheme}://{clean_fqdn}"
        return {
            "base_url": base,
            "ui_url": base,
            "api_url": f"{base}/xyn/api",
        }
    if public_hostname:
        host = str(public_hostname).strip().rstrip(".")
        return {
            "base_url": f"http://{host}:{ui_port}",
            "ui_url": f"http://{host}:{ui_port}",
            "api_url": f"http://{host}:{api_port}",
        }
    if public_ipv4:
        host = str(public_ipv4).strip()
        return {
            "base_url": f"http://{host}:{ui_port}",
            "ui_url": f"http://{host}:{ui_port}",
            "api_url": f"http://{host}:{api_port}",
        }
    raise RuntimeError("Unable to compute base URL: no fqdn/public hostname/public ipv4 available")


class SshDockerComposeInstanceDriver:
    def __init__(self, *, dry_run: bool = False) -> None:
        self.dry_run = bool(dry_run)

    def prepare(self, *, instance: Dict[str, Any], release_spec: Dict[str, Any]) -> PreparedPlan:
        network = instance.get("network") if isinstance(instance.get("network"), dict) else {}
        access = instance.get("access") if isinstance(instance.get("access"), dict) else {}
        ssh = access.get("ssh") if isinstance(access.get("ssh"), dict) else {}
        host = str(ssh.get("host") or (network or {}).get("public_hostname") or (network or {}).get("public_ipv4") or "").strip()
        user = str(ssh.get("user") or "ubuntu").strip()
        port = int(ssh.get("port") or 22)
        if not host:
            raise RuntimeError("Instance is missing ssh host/public hostname/public ipv4")

        params = release_spec.get("parameters") if isinstance(release_spec.get("parameters"), dict) else {}
        requested_ui_port = int(params.get("ui_port") or 0) or None
        requested_api_port = int(params.get("api_port") or 0) or None
        components = [row for row in (release_spec.get("components") or []) if isinstance(row, dict) and bool(row.get("enabled", True))]
        if not components:
            raise RuntimeError("ReleaseSpec has no enabled components")
        component_by_slug = {str(row.get("slug") or "").strip(): row for row in components}
        if "xyn-api" not in component_by_slug or "xyn-ui" not in component_by_slug:
            raise RuntimeError("ReleaseSpec must include enabled xyn-api and xyn-ui components")

        instance_label = str(params.get("instance_label") or "").strip() or _deterministic_short_id(f"{host}:{release_spec.get('name') or ''}")
        compose_project_prefix = str(params.get("compose_project_prefix") or "xyn").strip() or "xyn"
        compose_project = f"{compose_project_prefix}-{instance_label}".lower()
        remote_workdir = str(params.get("remote_workdir") or f"/opt/xyn/deployments/{compose_project}").strip()
        compose_file_path = f"{remote_workdir}/compose.yaml"

        if self.dry_run:
            used_ports: List[int] = []
        else:
            # Port list from remote host, one per line.
            private_key = str(((ssh.get("resolved") or {}).get("private_key") or "")).strip()
            if not private_key:
                raise RuntimeError("Resolved SSH private key is required for non-dry-run prepare")
            with SshExecutor(
                host=host,
                user=user,
                port=port,
                private_key=private_key,
                strict_host_key_checking=bool((ssh.get("resolved") or {}).get("strict_host_key_checking", False)),
                known_hosts=str((ssh.get("resolved") or {}).get("known_hosts") or ""),
            ) as executor:
                probe = executor.run("ss -ltnH | awk '{print $4}' | sed -E 's/.*://g' | sort -nu", check=False)
                used_ports = _parse_listening_ports(probe.stdout)

        ui_port, api_port = allocate_remote_ports(used_ports, requested_ui=requested_ui_port, requested_api=requested_api_port)

        services: Dict[str, Any] = {
            "xyn-api": {
                "image": str(component_by_slug["xyn-api"].get("image_ref") or "ghcr.io/xyence/xyn-api:latest"),
                "ports": [f"{api_port}:8000"],
                "environment": {
                    "DJANGO_SETTINGS_MODULE": "xyence.settings",
                    **(component_by_slug["xyn-api"].get("env") if isinstance(component_by_slug["xyn-api"].get("env"), dict) else {}),
                },
                "restart": "unless-stopped",
            },
            "xyn-ui": {
                "image": str(component_by_slug["xyn-ui"].get("image_ref") or "ghcr.io/xyence/xyn-ui:latest"),
                "ports": [f"{ui_port}:80"],
                "environment": {
                    "XYN_API_URL": "http://xyn-api:8000",
                    **(component_by_slug["xyn-ui"].get("env") if isinstance(component_by_slug["xyn-ui"].get("env"), dict) else {}),
                },
                "depends_on": ["xyn-api"],
                "restart": "unless-stopped",
            },
        }
        ems_component = component_by_slug.get("ems")
        ems_port: Optional[int] = None
        if ems_component and bool(ems_component.get("enabled", True)):
            ems_port = int(params.get("ems_port") or 0) or (ui_port + 10)
            services["ems"] = {
                "image": str(ems_component.get("image_ref") or "ghcr.io/xyence/ems:latest"),
                "ports": [f"{ems_port}:8080"],
                "restart": "unless-stopped",
            }

        compose_doc = {
            "services": services,
            "networks": {"default": {"name": f"{compose_project}-net"}},
        }
        compose_yaml = yaml.safe_dump(compose_doc, sort_keys=False)
        return PreparedPlan(
            compose_project=compose_project,
            remote_workdir=remote_workdir,
            compose_file_path=compose_file_path,
            compose_yaml=compose_yaml,
            ssh={
                "host": host,
                "user": user,
                "port": port,
                "resolved": ssh.get("resolved") if isinstance(ssh.get("resolved"), dict) else {},
            },
            ui_port=ui_port,
            api_port=api_port,
            ems_port=ems_port,
            components=components,
            fqdn=str(params.get("fqdn") or "").strip().rstrip("."),
            scheme=str(params.get("scheme") or "https").strip().lower() or "https",
        )

    def apply(self, prepared_plan: PreparedPlan) -> DriverResult:
        if self.dry_run:
            return DriverResult(
                status="pending",
                stdout="dry_run enabled; compose plan generated only",
                stderr="",
                details={
                    "compose_project": prepared_plan.compose_project,
                    "remote_workdir": prepared_plan.remote_workdir,
                    "compose_file": prepared_plan.compose_file_path,
                },
            )

        ssh_cfg = prepared_plan.ssh
        resolved = ssh_cfg.get("resolved") if isinstance(ssh_cfg.get("resolved"), dict) else {}
        private_key = str(resolved.get("private_key") or "").strip()
        if not private_key:
            raise RuntimeError("Resolved SSH private key is required")

        stdout_parts: List[str] = []
        stderr_parts: List[str] = []
        with SshExecutor(
            host=str(ssh_cfg.get("host") or ""),
            user=str(ssh_cfg.get("user") or "ubuntu"),
            port=int(ssh_cfg.get("port") or 22),
            private_key=private_key,
            strict_host_key_checking=bool(resolved.get("strict_host_key_checking", False)),
            known_hosts=str(resolved.get("known_hosts") or ""),
        ) as executor:
            executor.run(f"mkdir -p {shlex.quote(prepared_plan.remote_workdir)}")
            executor.upload_text(remote_path=prepared_plan.compose_file_path, content=prepared_plan.compose_yaml)
            up_cmd = (
                f"docker compose -p {shlex.quote(prepared_plan.compose_project)} "
                f"-f {shlex.quote(prepared_plan.compose_file_path)} up -d --pull always"
            )
            result = executor.run(up_cmd, timeout_seconds=300)
            stdout_parts.append(result.stdout)
            stderr_parts.append(result.stderr)

        return DriverResult(
            status="succeeded",
            stdout="\n".join([part for part in stdout_parts if part]),
            stderr="\n".join([part for part in stderr_parts if part]),
            details={
                "compose_project": prepared_plan.compose_project,
                "remote_workdir": prepared_plan.remote_workdir,
                "compose_file": prepared_plan.compose_file_path,
            },
        )

    def check_health(self, driver_result: DriverResult, release_spec: Dict[str, Any]) -> HealthResult:
        if self.dry_run:
            return HealthResult(status="pending", checks={"api": "pending", "ui": "pending", "reason": "dry_run"})

        params = release_spec.get("parameters") if isinstance(release_spec.get("parameters"), dict) else {}
        ssh_cfg = params.get("_prepared_ssh") if isinstance(params.get("_prepared_ssh"), dict) else {}
        private_key = str((ssh_cfg.get("resolved") or {}).get("private_key") or "").strip()
        if not private_key:
            return HealthResult(status="failed", checks={"error": "missing prepared ssh key"})

        api_port = int(params.get("_prepared_api_port") or 0)
        ui_port = int(params.get("_prepared_ui_port") or 0)
        checks: Dict[str, Any] = {"api": "pending", "ui": "pending"}
        deadline = time.time() + 90
        with SshExecutor(
            host=str(ssh_cfg.get("host") or ""),
            user=str(ssh_cfg.get("user") or "ubuntu"),
            port=int(ssh_cfg.get("port") or 22),
            private_key=private_key,
            strict_host_key_checking=bool((ssh_cfg.get("resolved") or {}).get("strict_host_key_checking", False)),
            known_hosts=str((ssh_cfg.get("resolved") or {}).get("known_hosts") or ""),
        ) as executor:
            while time.time() < deadline:
                api_ok = executor.run(
                    f"curl -fsS http://localhost:{api_port}/health >/dev/null",
                    check=False,
                    timeout_seconds=10,
                ).returncode == 0
                ui_ok = executor.run(
                    f"curl -fsS http://localhost:{ui_port}/ >/dev/null",
                    check=False,
                    timeout_seconds=10,
                ).returncode == 0
                checks["api"] = "ok" if api_ok else "retrying"
                checks["ui"] = "ok" if ui_ok else "retrying"
                if api_ok and ui_ok:
                    return HealthResult(status="succeeded", checks=checks)
                time.sleep(3)

        checks["api"] = "failed" if checks.get("api") != "ok" else checks["api"]
        checks["ui"] = "failed" if checks.get("ui") != "ok" else checks["ui"]
        return HealthResult(status="failed", checks=checks)
