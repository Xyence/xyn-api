import os
from pathlib import Path

from django.core.management.base import BaseCommand
from django.utils import timezone

from xyn_orchestrator.models import ContextPack


class Command(BaseCommand):
    help = "Seed canonical context packs from backend/context_packs." 

    def add_arguments(self, parser):
        parser.add_argument("--root", default=None, help="Optional context pack root directory")

    def handle(self, *args, **options):
        root = options.get("root")
        if not root:
            root = Path(__file__).resolve().parents[3] / "context_packs"
        root = Path(root)
        if not root.exists():
            self.stderr.write(f"Context pack root not found: {root}")
            return

        packs = [
            {
                "name": "xyn-planner-canon",
                "purpose": "planner",
                "scope": "global",
                "version": "1.0.0",
                "filename": "xyn-planner-canon.md",
                "is_default": True,
            },
            {
                "name": "xyn-coder-canon",
                "purpose": "coder",
                "scope": "global",
                "version": "1.0.0",
                "filename": "xyn-coder-canon.md",
                "is_default": True,
            },
            {
                "name": "ems-platform-blueprint",
                "purpose": "planner",
                "scope": "project",
                "project_key": "core.ems.platform",
                "version": "1.0.0",
                "filename": "ems-platform-blueprint.md",
                "is_default": False,
            },
        ]

        for pack in packs:
            path = root / pack["filename"]
            if not path.exists():
                self.stderr.write(f"Missing pack file: {path}")
                continue
            content = path.read_text(encoding="utf-8")
            defaults = {
                "purpose": pack["purpose"],
                "scope": pack["scope"],
                "version": pack["version"],
                "is_active": True,
                "is_default": pack.get("is_default", False),
                "namespace": pack.get("namespace", ""),
                "project_key": pack.get("project_key", ""),
                "content_markdown": content,
                "updated_at": timezone.now(),
            }
            obj, created = ContextPack.objects.update_or_create(
                name=pack["name"],
                purpose=pack["purpose"],
                scope=pack["scope"],
                version=pack["version"],
                namespace=defaults.get("namespace", ""),
                project_key=defaults.get("project_key", ""),
                defaults=defaults,
            )
            action = "Created" if created else "Updated"
            self.stdout.write(f"{action} {obj.name} ({obj.purpose}/{obj.scope})")
