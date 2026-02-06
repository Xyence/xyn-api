import json
from pathlib import Path

from django.core.management.base import BaseCommand

from xyn_orchestrator.models import Module


class Command(BaseCommand):
    help = "Seed module specs from backend/registry/modules."

    def handle(self, *args, **options):
        registry_root = Path(__file__).resolve().parents[3] / "registry" / "modules"
        if not registry_root.exists():
            self.stdout.write(self.style.WARNING("No module registry directory found."))
            return
        count = 0
        for path in registry_root.glob("*.json"):
            spec = json.loads(path.read_text(encoding="utf-8"))
            metadata = spec.get("metadata", {})
            name = metadata.get("name")
            namespace = metadata.get("namespace")
            version = metadata.get("version")
            if not (name and namespace and version):
                self.stdout.write(self.style.WARNING(f"Skipping {path.name}: missing metadata"))
                continue
            module, _ = Module.objects.get_or_create(
                name=name,
                namespace=namespace,
                defaults={
                    "fqn": spec.get("module", {}).get("fqn") or f"{namespace}.{name}",
                    "type": spec.get("module", {}).get("type", "lib"),
                    "current_version": version,
                    "latest_module_spec_json": spec,
                    "capabilities_provided_json": spec.get("module", {}).get("capabilitiesProvided", []),
                    "interfaces_json": spec.get("module", {}).get("interfaces", {}),
                    "dependencies_json": spec.get("module", {}).get("dependencies", {}),
                },
            )
            updated_fields = []
            if module.fqn != (spec.get("module", {}).get("fqn") or f"{namespace}.{name}"):
                module.fqn = spec.get("module", {}).get("fqn") or f"{namespace}.{name}"
                updated_fields.append("fqn")
            if module.type != spec.get("module", {}).get("type", "lib"):
                module.type = spec.get("module", {}).get("type", "lib")
                updated_fields.append("type")
            if module.current_version != version:
                module.current_version = version
                updated_fields.append("current_version")
            if module.latest_module_spec_json != spec:
                module.latest_module_spec_json = spec
                updated_fields.append("latest_module_spec_json")
            caps = spec.get("module", {}).get("capabilitiesProvided", [])
            if module.capabilities_provided_json != caps:
                module.capabilities_provided_json = caps
                updated_fields.append("capabilities_provided_json")
            interfaces = spec.get("module", {}).get("interfaces", {})
            if module.interfaces_json != interfaces:
                module.interfaces_json = interfaces
                updated_fields.append("interfaces_json")
            dependencies = spec.get("module", {}).get("dependencies", {})
            if module.dependencies_json != dependencies:
                module.dependencies_json = dependencies
                updated_fields.append("dependencies_json")
            if updated_fields:
                module.save(update_fields=[*updated_fields, "updated_at"])
            count += 1
        self.stdout.write(self.style.SUCCESS(f"Seeded {count} module(s)."))
