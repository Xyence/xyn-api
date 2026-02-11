from django.test import TestCase

from xyn_orchestrator.models import ProvisionedInstance
from xyn_orchestrator.provisioning_views import _is_local_instance


class ProvisioningViewsTests(TestCase):
    def test_ec2_instance_id_is_not_treated_as_local(self):
        instance = ProvisionedInstance(
            name="xyn-seed-dev-1",
            aws_region="us-west-2",
            instance_id="i-0123456789abcdef0",
            runtime_substrate="local",
            instance_type="t3.small",
            ami_id="ami-12345678",
        )
        self.assertFalse(_is_local_instance(instance))

