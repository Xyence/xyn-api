from django.core.management.base import BaseCommand

from xyn_orchestrator.models import RoleBinding, UserIdentity


class Command(BaseCommand):
    help = "Grant a role to a user identity."

    def add_arguments(self, parser):
        parser.add_argument("--issuer", required=True)
        parser.add_argument("--subject", required=True)
        parser.add_argument("--role", required=True)
        parser.add_argument("--scope-kind", default="platform")
        parser.add_argument("--scope-id", default="")

    def handle(self, *args, **options):
        issuer = options["issuer"]
        subject = options["subject"]
        role = options["role"]
        scope_kind = options["scope_kind"]
        scope_id = options["scope_id"] or None
        identity = UserIdentity.objects.filter(issuer=issuer, subject=subject).first()
        if not identity:
            self.stderr.write("UserIdentity not found for issuer/subject.")
            return
        binding, created = RoleBinding.objects.get_or_create(
            user_identity=identity,
            scope_kind=scope_kind,
            scope_id=scope_id,
            role=role,
        )
        if created:
            self.stdout.write("Role granted.")
        else:
            self.stdout.write("Role already present.")
