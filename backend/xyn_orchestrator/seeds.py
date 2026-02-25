import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from django.db import transaction
from django.utils import timezone

from .models import ContextPack, SeedApplication, SeedApplicationItem, SeedItem, SeedPack, UserIdentity

logger = logging.getLogger(__name__)

SEED_ENTITY_CONTEXT_PACK = "context_pack"
DEFAULT_SEEDS_DIR = Path(__file__).resolve().parents[1] / "seeds"


@dataclass
class SeedChange:
    action: str
    target_entity_id: Optional[str] = None
    message: str = ""


def _normalized_json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _payload_hash(payload: Any) -> str:
    return hashlib.sha256(_normalized_json(payload).encode("utf-8")).hexdigest()


def _normalize_markdown(value: str) -> str:
    return str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()


def _context_pack_seed_hash(payload: Dict[str, Any]) -> str:
    canonical = {
        "name": str(payload.get("name") or payload.get("slug") or "").strip(),
        "purpose": str(payload.get("purpose") or "any").strip(),
        "scope": str(payload.get("scope") or "global").strip(),
        "namespace": str(payload.get("namespace") or "").strip(),
        "project_key": str(payload.get("project_key") or "").strip(),
        "version": str(payload.get("version") or "").strip(),
        "is_active": bool(payload.get("is_active", True)),
        "is_default": bool(payload.get("is_default", False)),
        "content_markdown": _normalize_markdown(str(payload.get("content") or payload.get("content_markdown") or "")),
        "applies_to_json": payload.get("applies_to_json") if isinstance(payload.get("applies_to_json"), dict) else {},
    }
    return _payload_hash(canonical)


def _context_pack_current_hash(pack: ContextPack) -> str:
    canonical = {
        "name": pack.name,
        "purpose": pack.purpose,
        "scope": pack.scope,
        "namespace": pack.namespace or "",
        "project_key": pack.project_key or "",
        "version": pack.version,
        "is_active": bool(pack.is_active),
        "is_default": bool(pack.is_default),
        "content_markdown": _normalize_markdown(pack.content_markdown),
        "applies_to_json": pack.applies_to_json if isinstance(pack.applies_to_json, dict) else {},
    }
    return _payload_hash(canonical)


def _parse_seed_file(path: Path) -> Optional[Dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Skipping invalid seed file %s: %s", path, exc)
        return None
    if not isinstance(payload, dict):
        return None
    pack = payload.get("seed_pack")
    items = payload.get("items")
    if not isinstance(pack, dict) or not isinstance(items, list):
        return None
    return payload


def _seed_files(root: Optional[Path] = None) -> List[Path]:
    seeds_root = Path(root) if root else DEFAULT_SEEDS_DIR
    if not seeds_root.exists():
        return []
    return sorted(p for p in seeds_root.glob("*.json") if p.is_file())


def sync_seed_registry(*, root: Optional[Path] = None) -> List[SeedPack]:
    synced: List[SeedPack] = []
    seen_slugs: set[str] = set()
    for file_path in _seed_files(root):
        payload = _parse_seed_file(file_path)
        if not payload:
            continue
        pack_meta = payload.get("seed_pack") or {}
        slug = str(pack_meta.get("slug") or "").strip()
        if not slug:
            continue
        seen_slugs.add(slug)
        pack, _ = SeedPack.objects.update_or_create(
            slug=slug,
            defaults={
                "name": str(pack_meta.get("name") or slug),
                "description": str(pack_meta.get("description") or ""),
                "version": str(pack_meta.get("version") or "v0"),
                "scope": str(pack_meta.get("scope") or "optional"),
                "namespace": str(pack_meta.get("namespace") or ""),
            },
        )
        item_refs: set[Tuple[str, str]] = set()
        for item in payload.get("items") or []:
            if not isinstance(item, dict):
                continue
            entity_type = str(item.get("entity_type") or "").strip()
            unique_key = item.get("unique_key") if isinstance(item.get("unique_key"), dict) else {}
            payload_json = item.get("payload") if isinstance(item.get("payload"), dict) else {}
            if not entity_type:
                continue
            entity_slug = str(item.get("entity_slug") or unique_key.get("slug") or unique_key.get("name") or payload_json.get("slug") or payload_json.get("name") or "").strip()
            if not entity_slug:
                continue
            content_hash = _context_pack_seed_hash(payload_json) if entity_type == SEED_ENTITY_CONTEXT_PACK else _payload_hash(payload_json)
            SeedItem.objects.update_or_create(
                seed_pack=pack,
                entity_type=entity_type,
                entity_slug=entity_slug,
                defaults={
                    "entity_unique_key_json": unique_key,
                    "payload_json": payload_json,
                    "content_hash": content_hash,
                },
            )
            item_refs.add((entity_type, entity_slug))
        if item_refs:
            for row in SeedItem.objects.filter(seed_pack=pack):
                if (row.entity_type, row.entity_slug) not in item_refs:
                    row.delete()
        synced.append(pack)
    return synced


def _resolve_context_pack_lookup(unique_key: Dict[str, Any], payload: Dict[str, Any], entity_slug: str) -> Dict[str, Any]:
    scope = str(unique_key.get("scope") or payload.get("scope") or "global").strip() or "global"
    lookup: Dict[str, Any] = {"scope": scope}
    name = str(unique_key.get("slug") or unique_key.get("name") or payload.get("slug") or payload.get("name") or entity_slug).strip()
    lookup["name"] = name
    if scope == "namespace":
        lookup["namespace"] = str(unique_key.get("namespace") or payload.get("namespace") or "").strip()
    elif scope == "project":
        lookup["project_key"] = str(unique_key.get("project_key") or payload.get("project_key") or "").strip()
    return lookup


def _context_pack_defaults(payload: Dict[str, Any], entity_slug: str, pack: SeedPack, item_hash: str) -> Dict[str, Any]:
    name = str(payload.get("name") or payload.get("slug") or entity_slug).strip()
    defaults = {
        "name": name,
        "purpose": str(payload.get("purpose") or "any").strip() or "any",
        "scope": str(payload.get("scope") or "global").strip() or "global",
        "namespace": str(payload.get("namespace") or "").strip(),
        "project_key": str(payload.get("project_key") or "").strip(),
        "version": str(payload.get("version") or pack.version or "1.0.0").strip() or "1.0.0",
        "is_active": bool(payload.get("is_active", True)),
        "is_default": bool(payload.get("is_default", False)),
        "content_markdown": str(payload.get("content") or payload.get("content_markdown") or ""),
        "applies_to_json": payload.get("applies_to_json") if isinstance(payload.get("applies_to_json"), dict) else {},
        "seeded_by_pack_slug": pack.slug,
        "seeded_version": pack.version,
        "seeded_content_hash": item_hash,
        "seeded_at": timezone.now(),
    }
    if defaults["scope"] != "namespace":
        defaults["namespace"] = ""
    if defaults["scope"] != "project":
        defaults["project_key"] = ""
    return defaults


def _apply_context_pack_item(pack: SeedPack, item: SeedItem, *, dry_run: bool = False) -> SeedChange:
    payload = item.payload_json if isinstance(item.payload_json, dict) else {}
    lookup = _resolve_context_pack_lookup(item.entity_unique_key_json if isinstance(item.entity_unique_key_json, dict) else {}, payload, item.entity_slug)
    existing = ContextPack.objects.filter(**lookup).order_by("-updated_at").first()
    defaults = _context_pack_defaults(payload, item.entity_slug, pack, item.content_hash)

    if existing is None:
        if dry_run:
            return SeedChange(action="created", target_entity_id=None, message="would create context pack")
        row = ContextPack.objects.create(**defaults)
        return SeedChange(action="created", target_entity_id=str(row.id), message="context pack created")

    managed_fields = [
        "name",
        "purpose",
        "scope",
        "namespace",
        "project_key",
        "version",
        "is_active",
        "is_default",
        "content_markdown",
        "applies_to_json",
        "seeded_by_pack_slug",
        "seeded_version",
        "seeded_content_hash",
        "seeded_at",
    ]
    changed_fields: List[str] = []
    for field in managed_fields:
        next_value = defaults[field]
        current_value = getattr(existing, field)
        if field == "seeded_at":
            if existing.seeded_content_hash != item.content_hash or existing.seeded_version != pack.version or existing.seeded_by_pack_slug != pack.slug:
                changed_fields.append(field)
            continue
        if current_value != next_value:
            changed_fields.append(field)

    if not changed_fields:
        return SeedChange(action="unchanged", target_entity_id=str(existing.id), message="already up to date")

    if dry_run:
        return SeedChange(action="updated", target_entity_id=str(existing.id), message="would update context pack")

    for field in changed_fields:
        setattr(existing, field, defaults[field])
    existing.save(update_fields=changed_fields + ["updated_at"])
    return SeedChange(action="updated", target_entity_id=str(existing.id), message="context pack updated")


def _apply_seed_item(pack: SeedPack, item: SeedItem, *, dry_run: bool = False) -> SeedChange:
    if item.entity_type == SEED_ENTITY_CONTEXT_PACK:
        return _apply_context_pack_item(pack, item, dry_run=dry_run)
    return SeedChange(action="skipped", message=f"unsupported entity_type {item.entity_type}")


def _empty_summary(pack: SeedPack, *, dry_run: bool = False) -> Dict[str, Any]:
    return {
        "pack_slug": pack.slug,
        "pack_version": pack.version,
        "dry_run": dry_run,
        "created": 0,
        "updated": 0,
        "unchanged": 0,
        "skipped": 0,
        "failed": 0,
        "items": [],
    }


def _increment(summary: Dict[str, Any], action: str) -> None:
    if action not in {"created", "updated", "unchanged", "skipped", "failed"}:
        action = "failed"
    summary[action] = int(summary.get(action, 0)) + 1


def apply_seed_pack(
    seed_pack: SeedPack,
    *,
    dry_run: bool = False,
    applied_by: Optional[UserIdentity] = None,
) -> Dict[str, Any]:
    summary = _empty_summary(seed_pack, dry_run=dry_run)
    application: Optional[SeedApplication] = None
    if not dry_run:
        application = SeedApplication.objects.create(
            seed_pack=seed_pack,
            applied_by=applied_by,
            status="succeeded",
            result_summary_json={},
        )

    for item in seed_pack.items.order_by("entity_type", "entity_slug"):
        try:
            change = _apply_seed_item(seed_pack, item, dry_run=dry_run)
            _increment(summary, change.action)
            summary["items"].append(
                {
                    "seed_item_id": str(item.id),
                    "entity_type": item.entity_type,
                    "entity_slug": item.entity_slug,
                    "action": change.action,
                    "target_entity_id": change.target_entity_id,
                    "message": change.message,
                }
            )
            if application:
                SeedApplicationItem.objects.create(
                    seed_application=application,
                    seed_item=item,
                    action=change.action,
                    target_entity_id=change.target_entity_id,
                    message=change.message,
                )
        except Exception as exc:
            logger.exception("seed apply failed for %s/%s", seed_pack.slug, item.entity_slug)
            _increment(summary, "failed")
            msg = str(exc)
            summary["items"].append(
                {
                    "seed_item_id": str(item.id),
                    "entity_type": item.entity_type,
                    "entity_slug": item.entity_slug,
                    "action": "failed",
                    "target_entity_id": None,
                    "message": msg,
                }
            )
            if application:
                SeedApplicationItem.objects.create(
                    seed_application=application,
                    seed_item=item,
                    action="failed",
                    message=msg,
                )

    if application:
        status = "failed" if summary.get("failed") else "succeeded"
        application.status = status
        application.result_summary_json = {
            "created": summary.get("created", 0),
            "updated": summary.get("updated", 0),
            "unchanged": summary.get("unchanged", 0),
            "skipped": summary.get("skipped", 0),
            "failed": summary.get("failed", 0),
        }
        if status == "failed":
            application.error_message = "One or more seed items failed to apply"
        application.save(update_fields=["status", "result_summary_json", "error_message"])
        summary["application_id"] = str(application.id)
    else:
        summary["application_id"] = None
    return summary


def _selected_packs(*, pack_slugs: Optional[Iterable[str]] = None, apply_core: bool = False) -> List[SeedPack]:
    qs = SeedPack.objects.all().order_by("slug")
    if pack_slugs:
        slugs = [str(item).strip() for item in pack_slugs if str(item).strip()]
        return list(qs.filter(slug__in=slugs))
    if apply_core:
        return list(qs.filter(scope="core"))
    return list(qs)


def apply_seed_packs(
    *,
    pack_slugs: Optional[Iterable[str]] = None,
    apply_core: bool = False,
    dry_run: bool = False,
    applied_by: Optional[UserIdentity] = None,
) -> Dict[str, Any]:
    sync_seed_registry()
    packs = _selected_packs(pack_slugs=pack_slugs, apply_core=apply_core)
    results: List[Dict[str, Any]] = []
    totals = {"created": 0, "updated": 0, "unchanged": 0, "skipped": 0, "failed": 0}
    for pack in packs:
        with transaction.atomic():
            result = apply_seed_pack(pack, dry_run=dry_run, applied_by=applied_by)
        results.append(result)
        for key in totals:
            totals[key] += int(result.get(key, 0))
    return {
        "pack_count": len(packs),
        "dry_run": dry_run,
        "results": results,
        "summary": totals,
    }


def detect_seed_item_status(item: SeedItem) -> str:
    if item.entity_type != SEED_ENTITY_CONTEXT_PACK:
        return "skipped"
    payload = item.payload_json if isinstance(item.payload_json, dict) else {}
    lookup = _resolve_context_pack_lookup(item.entity_unique_key_json if isinstance(item.entity_unique_key_json, dict) else {}, payload, item.entity_slug)
    target = ContextPack.objects.filter(**lookup).order_by("-updated_at").first()
    if not target:
        return "missing"
    if target.seeded_by_pack_slug != item.seed_pack.slug:
        return "drifted"
    if _context_pack_current_hash(target) == item.content_hash:
        return "matches"
    return "drifted"


def _pack_status(pack: SeedPack) -> Dict[str, Any]:
    items = list(pack.items.order_by("entity_type", "entity_slug"))
    missing = 0
    matches = 0
    drifted = 0
    skipped = 0
    item_rows: List[Dict[str, Any]] = []
    for item in items:
        status = detect_seed_item_status(item)
        if status == "missing":
            missing += 1
        elif status == "matches":
            matches += 1
        elif status == "drifted":
            drifted += 1
        else:
            skipped += 1
        item_rows.append(
            {
                "id": str(item.id),
                "entity_type": item.entity_type,
                "entity_slug": item.entity_slug,
                "status": status,
                "content_hash": item.content_hash,
                "entity_unique_key_json": item.entity_unique_key_json if isinstance(item.entity_unique_key_json, dict) else {},
            }
        )
    last_application = pack.applications.order_by("-applied_at").first()
    return {
        "slug": pack.slug,
        "name": pack.name,
        "description": pack.description,
        "version": pack.version,
        "scope": pack.scope,
        "namespace": pack.namespace,
        "last_applied": last_application.applied_at.isoformat() if last_application else None,
        "last_status": last_application.status if last_application else None,
        "last_summary": last_application.result_summary_json if last_application else None,
        "item_count": len(items),
        "missing_count": missing,
        "matches_count": matches,
        "drifted_count": drifted,
        "skipped_count": skipped,
        "items": item_rows,
    }


def list_seed_packs_status(*, include_items: bool = False, root: Optional[Path] = None) -> List[Dict[str, Any]]:
    sync_seed_registry(root=root)
    rows = []
    for pack in SeedPack.objects.all().order_by("scope", "slug"):
        status = _pack_status(pack)
        if not include_items:
            status.pop("items", None)
        rows.append(status)
    return rows


def get_seed_pack_status(slug: str) -> Optional[Dict[str, Any]]:
    sync_seed_registry()
    pack = SeedPack.objects.filter(slug=slug).first()
    if not pack:
        return None
    return _pack_status(pack)


def auto_apply_core_seed_packs() -> None:
    if str(os.environ.get("XYN_DISABLE_CORE_SEED_AUTO_APPLY") or "").strip().lower() in {"1", "true", "yes", "on"}:
        return
    sync_seed_registry()
    core_packs = SeedPack.objects.filter(scope="core")
    if not core_packs.exists():
        return
    for pack in core_packs:
        last = pack.applications.order_by("-applied_at").first()
        if last and last.status == "succeeded" and int((last.result_summary_json or {}).get("failed", 0)) == 0:
            continue
        apply_seed_pack(pack, dry_run=False, applied_by=None)
