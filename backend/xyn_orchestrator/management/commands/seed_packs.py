import json

from django.core.management.base import BaseCommand, CommandError

from xyn_orchestrator.models import UserIdentity
from xyn_orchestrator.seeds import apply_seed_packs, list_seed_packs_status


class Command(BaseCommand):
    help = "Apply Xyn Seed Packs (core or selected packs)."

    def add_arguments(self, parser):
        parser.add_argument("--core", action="store_true", help="Apply only core packs")
        parser.add_argument("--pack", action="append", dest="packs", help="Apply a specific seed pack slug")
        parser.add_argument("--dry-run", action="store_true", help="Compute changes without writing")
        parser.add_argument("--list", action="store_true", help="List registered seed packs and status")
        parser.add_argument("--applied-by", dest="applied_by", help="Optional UserIdentity UUID")

    def handle(self, *args, **options):
        if options.get("list"):
            rows = list_seed_packs_status(include_items=False)
            self.stdout.write(json.dumps({"packs": rows}, indent=2, default=str))
            return

        applied_by = None
        applied_by_id = options.get("applied_by")
        if applied_by_id:
            applied_by = UserIdentity.objects.filter(id=applied_by_id).first()
            if not applied_by:
                raise CommandError("applied_by identity not found")

        result = apply_seed_packs(
            pack_slugs=options.get("packs") or None,
            apply_core=bool(options.get("core")),
            dry_run=bool(options.get("dry_run")),
            applied_by=applied_by,
        )
        self.stdout.write(json.dumps(result, indent=2, default=str))
