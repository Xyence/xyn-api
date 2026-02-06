from django.core.management.base import BaseCommand

from xyn_orchestrator.models import ProvisionedInstance
from xyn_orchestrator.provisioning import refresh_instance, fetch_bootstrap_log


class Command(BaseCommand):
    help = "Smoke test EC2 provisioning integration (refresh + bootstrap log)."

    def add_arguments(self, parser):
        parser.add_argument("--instance-id", help="ProvisionedInstance UUID to refresh")
        parser.add_argument("--tail", type=int, default=50, help="Log tail lines")

    def handle(self, *args, **options):
        instance_id = options.get("instance_id")
        if not instance_id:
            count = ProvisionedInstance.objects.count()
            self.stdout.write(f"Provisioned instances in DB: {count}")
            return
        instance = ProvisionedInstance.objects.get(id=instance_id)
        instance = refresh_instance(instance)
        self.stdout.write(f"Status: {instance.status} (SSM: {instance.ssm_status})")
        log = fetch_bootstrap_log(instance, tail=options["tail"])
        self.stdout.write(f"Log status: {log.get('status')}")
