import json
import os
from pathlib import Path
from typing import Dict, List, Tuple

from django.utils import timezone

from xyn_orchestrator.models import Module

_LAST_SYNC: float = 0.0


def _registry_root() -> Path:
    return Path(__file__).resolve().parents[1] / "registry" / "modules"


def _load_specs(root: Path) -> List[Tuple[str, Dict]]:
    specs: List[Tuple[str, Dict]] = []
    for path in sorted(root.glob("*.json")):
        try:
            content = json.loads(path.read_text(encoding="utf-8"))
            specs.append((path.stem, content))
        except json.JSONDecodeError:
            continue
    return specs


def sync_modules_from_registry(root: Path | None = None) -> int:
    registry_root = root or _registry_root()
    if not registry_root.exists():
        return 0
    count = 0
    for name, spec in _load_specs(registry_root):
        metadata = spec.get("metadata", {})
        module_spec = spec.get("module", {})
        namespace = metadata.get("namespace", "core")
        version = metadata.get("version", "0.1.0")
        fqn = module_spec.get("fqn") or f"{namespace}.{name}"
        module, created = Module.objects.get_or_create(
            fqn=fqn,
            defaults={
                "name": name,
                "namespace": namespace,
                "type": module_spec.get("type", "lib"),
                "current_version": version,
                "latest_module_spec_json": spec,
                "capabilities_provided_json": module_spec.get("capabilitiesProvided", []),
                "interfaces_json": module_spec.get("interfaces", {}),
                "dependencies_json": module_spec.get("dependencies", {}),
                "updated_at": timezone.now(),
            },
        )
        if created:
            count += 1
            continue
        updated_fields = []
        if module.name != name:
            module.name = name
            updated_fields.append("name")
        if module.namespace != namespace:
            module.namespace = namespace
            updated_fields.append("namespace")
        if module.type != module_spec.get("type", module.type):
            module.type = module_spec.get("type", module.type)
            updated_fields.append("type")
        if module.current_version != version:
            module.current_version = version
            updated_fields.append("current_version")
        if module.latest_module_spec_json != spec:
            module.latest_module_spec_json = spec
            updated_fields.append("latest_module_spec_json")
        caps = module_spec.get("capabilitiesProvided", [])
        if module.capabilities_provided_json != caps:
            module.capabilities_provided_json = caps
            updated_fields.append("capabilities_provided_json")
        interfaces = module_spec.get("interfaces", {})
        if module.interfaces_json != interfaces:
            module.interfaces_json = interfaces
            updated_fields.append("interfaces_json")
        dependencies = module_spec.get("dependencies", {})
        if module.dependencies_json != dependencies:
            module.dependencies_json = dependencies
            updated_fields.append("dependencies_json")
        if updated_fields:
            module.updated_at = timezone.now()
            module.save(update_fields=updated_fields + ["updated_at"])
    return count


def maybe_sync_modules_from_registry() -> int:
    global _LAST_SYNC
    if os.environ.get("XYN_MODULE_REGISTRY_AUTOSYNC", "1") != "1":
        return 0
    interval = int(os.environ.get("XYN_MODULE_REGISTRY_SYNC_INTERVAL", "60"))
    now = timezone.now().timestamp()
    if now - _LAST_SYNC < interval:
        return 0
    _LAST_SYNC = now
    return sync_modules_from_registry()
