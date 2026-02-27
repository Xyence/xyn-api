from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from django.core.management.base import BaseCommand
from django.db import transaction

from xyn_orchestrator.artifact_links import ensure_context_pack_artifact
from xyn_orchestrator.models import AgentDefinition, ContextPack


MIGRATION_PACK_SLUG = "xyn-agent-system-prompts-migration"
MIGRATION_VERSION = "v1.0.0"


def _normalize_refs(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    refs: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        value = str(entry.get("id") or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        refs.append(dict(entry))
    return refs


class Command(BaseCommand):
    help = "Migrates AgentDefinition.system_prompt_text into canonical context packs and attaches them as agent defaults."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Preview changes without writing records.")
        parser.add_argument(
            "--keep-override",
            action="store_true",
            help="Do not clear system_prompt_text after migration (keeps non-governed override text).",
        )

    def handle(self, *args, **options):
        dry_run = bool(options.get("dry_run"))
        keep_override = bool(options.get("keep_override"))
        migrated = 0
        updated_agents = 0
        created_packs = 0

        qs = AgentDefinition.objects.all().order_by("slug")
        for agent in qs:
            prompt_text = str(agent.system_prompt_text or "").strip()
            if not prompt_text:
                continue
            migrated += 1
            pack_slug = f"agent:{agent.slug}:system"
            content_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
            defaults = {
                "purpose": "any",
                "scope": "global",
                "namespace": "",
                "project_key": "",
                "version": MIGRATION_VERSION,
                "is_active": True,
                "is_default": False,
                "content_markdown": prompt_text,
                "applies_to_json": {
                    "agent_slug": agent.slug,
                    "tags": ["agent-system", "migration"],
                },
                "seeded_by_pack_slug": MIGRATION_PACK_SLUG,
                "seeded_version": MIGRATION_VERSION,
                "seeded_content_hash": content_hash,
            }
            existing = ContextPack.objects.filter(name=pack_slug, scope="global", purpose="any").order_by("-updated_at").first()
            if existing:
                pack = existing
                created = False
            else:
                pack = ContextPack(**defaults, name=pack_slug)
                created = True

            current_refs = _normalize_refs(agent.context_pack_refs_json)
            existing_ids = {str(item.get("id") or "").strip() for item in current_refs}

            if dry_run:
                action = "create" if created else "update"
                self.stdout.write(f"[dry-run] {action} {pack_slug} and attach to agent {agent.slug}")
                continue

            with transaction.atomic():
                if created:
                    pack.save()
                    created_packs += 1
                else:
                    # Keep canonical migration pack synced with current prompt text.
                    if pack.content_markdown != prompt_text or not pack.is_active or pack.version != MIGRATION_VERSION:
                        pack.content_markdown = prompt_text
                        pack.version = MIGRATION_VERSION
                        pack.is_active = True
                        pack.seeded_by_pack_slug = MIGRATION_PACK_SLUG
                        pack.seeded_version = MIGRATION_VERSION
                        pack.seeded_content_hash = content_hash
                        pack.save(
                            update_fields=[
                                "content_markdown",
                                "version",
                                "is_active",
                                "seeded_by_pack_slug",
                                "seeded_version",
                                "seeded_content_hash",
                                "updated_at",
                            ]
                        )
                ensure_context_pack_artifact(pack, owner_user=None)

                if str(pack.id) not in existing_ids:
                    current_refs.insert(
                        0,
                        {
                            "id": str(pack.id),
                            "name": pack.name,
                            "purpose": pack.purpose,
                            "scope": pack.scope,
                            "version": pack.version,
                        },
                    )
                agent.context_pack_refs_json = current_refs
                if not keep_override:
                    agent.system_prompt_text = ""
                    agent.save(update_fields=["context_pack_refs_json", "system_prompt_text", "updated_at"])
                else:
                    agent.save(update_fields=["context_pack_refs_json", "updated_at"])
                updated_agents += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Processed {migrated} agent prompts; updated agents={updated_agents}, created context packs={created_packs}."
            )
        )
