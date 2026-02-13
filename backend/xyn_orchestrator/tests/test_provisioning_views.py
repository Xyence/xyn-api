from django.contrib.auth import get_user_model
from django.test import TestCase
from unittest import mock

from xyn_orchestrator.models import ProvisionedInstance
from xyn_orchestrator.provisioning_views import _is_local_instance


class ProvisioningViewsTests(TestCase):
    @mock.patch("xyn_orchestrator.provisioning_views.get_instance_metadata", side_effect=RuntimeError("no metadata"))
    def test_ec2_instance_id_is_not_treated_as_local(self, _mock_metadata):
        instance = ProvisionedInstance(
            name="xyn-seed-dev-1",
            aws_region="us-west-2",
            instance_id="i-0123456789abcdef0",
            runtime_substrate="ec2",
            instance_type="t3.small",
            ami_id="ami-12345678",
        )
        self.assertFalse(_is_local_instance(instance))

    @mock.patch("xyn_orchestrator.provisioning_views.get_instance_metadata")
    def test_ec2_instance_matching_runtime_host_is_treated_as_local(self, mock_metadata):
        mock_metadata.return_value = mock.Mock(instance_id="i-0123456789abcdef0")
        instance = ProvisionedInstance(
            name="xyence-1",
            aws_region="us-west-2",
            instance_id="i-0123456789abcdef0",
            runtime_substrate="ec2",
            instance_type="t3.small",
            ami_id="ami-12345678",
        )
        self.assertTrue(_is_local_instance(instance))

    def test_instance_containers_returns_unavailable_for_offline_ssm(self):
        user = get_user_model().objects.create_user(
            username="staff-user",
            password="x",
            is_staff=True,
        )
        self.client.force_login(user)
        instance = ProvisionedInstance.objects.create(
            name="xyence-1",
            aws_region="us-west-2",
            instance_id="i-0aaaaaaaaaaaaaaa1",
            runtime_substrate="ec2",
            instance_type="t3.small",
            ami_id="ami-12345678",
            status="running",
            ssm_status="Offline",
        )

        response = self.client.get(f"/xyn/api/provision/instances/{instance.id}/containers")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload.get("status"), "unavailable")
        self.assertEqual(payload.get("ssm_status"), "Offline")
        self.assertEqual(payload.get("containers"), [])
        self.assertIn("not in a runnable state", (payload.get("error") or "").lower())
