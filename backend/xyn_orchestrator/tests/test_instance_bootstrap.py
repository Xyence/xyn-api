import os
from unittest import mock

from django.test import TestCase

from xyn_orchestrator.instances import bootstrap


class InstanceBootstrapTests(TestCase):
    def setUp(self) -> None:
        os.environ.pop("XYENCE_RUNTIME_SUBSTRATE", None)
        os.environ.pop("ECS_CONTAINER_METADATA_URI_V4", None)
        os.environ.pop("KUBERNETES_SERVICE_HOST", None)
        os.environ.pop("XYENCE_LOCAL_INSTANCE_ID", None)
        os.environ.pop("XYENCE_LOCAL_INSTANCE_NAME", None)

    def test_discover_ec2_identity_from_imds(self) -> None:
        def make_response(status=200, text="", payload=None):
            resp = mock.Mock()
            resp.status_code = status
            resp.text = text
            resp.json.return_value = payload or {}
            resp.raise_for_status.return_value = None
            return resp

        identity = {
            "instanceId": "i-12345",
            "region": "us-west-2",
            "instanceType": "t3.small",
            "imageId": "ami-abc123",
        }
        with mock.patch("xyn_orchestrator.instances.bootstrap.requests.put") as put_mock:
            with mock.patch("xyn_orchestrator.instances.bootstrap.requests.get") as get_mock:
                put_mock.return_value = make_response(text="token")
                get_mock.side_effect = [
                    make_response(payload=identity),
                    make_response(text="host.internal"),
                ]
                metadata = bootstrap.discover_ec2_identity()
        self.assertIsNotNone(metadata)
        assert metadata
        self.assertEqual(metadata.instance_id, "i-12345")
        self.assertEqual(metadata.region, "us-west-2")
        self.assertEqual(metadata.instance_type, "t3.small")
        self.assertEqual(metadata.ami_id, "ami-abc123")

    def test_discover_fargate_identity(self) -> None:
        os.environ["ECS_CONTAINER_METADATA_URI_V4"] = "http://127.0.0.1/metadata"
        task_payload = {
            "TaskARN": "arn:aws:ecs:us-west-2:123456789012:task/cluster/abc",
            "Family": "xyn-seed",
            "Revision": 12,
            "LaunchType": "FARGATE",
        }
        with mock.patch("xyn_orchestrator.instances.bootstrap.requests.get") as get_mock:
            resp = mock.Mock()
            resp.json.return_value = task_payload
            resp.raise_for_status.return_value = None
            get_mock.return_value = resp
            metadata = bootstrap.discover_fargate_identity()
        self.assertIsNotNone(metadata)
        assert metadata
        self.assertIn("task/cluster/abc", metadata.instance_id)
        self.assertEqual(metadata.region, "us-west-2")

    def test_discover_k8s_identity(self) -> None:
        os.environ["KUBERNETES_SERVICE_HOST"] = "10.0.0.1"
        os.environ["HOSTNAME"] = "xyn-api-pod"
        with mock.patch("xyn_orchestrator.instances.bootstrap._read_file") as read_mock:
            read_mock.return_value = "default"
            metadata = bootstrap.discover_k8s_identity()
        self.assertIsNotNone(metadata)
        assert metadata
        self.assertIn("k8s", metadata.instance_id)
        self.assertEqual(metadata.name, "xyn-api-pod")

    def test_env_override_precedence(self) -> None:
        os.environ["XYENCE_LOCAL_INSTANCE_ID"] = "override-id"
        os.environ["XYENCE_LOCAL_INSTANCE_NAME"] = "override-name"
        metadata = bootstrap.discover_local_identity()
        overridden = bootstrap._apply_overrides(metadata)
        self.assertEqual(overridden.instance_id, "override-id")
        self.assertEqual(overridden.name, "override-name")

    def test_upsert_creates_instance(self) -> None:
        metadata = bootstrap.InstanceMetadata(
            substrate="local",
            instance_id="local:test-host",
            name="test-host",
            region="local",
            instance_type="local",
            ami_id="local",
            status="running",
        )
        with mock.patch("xyn_orchestrator.instances.bootstrap.get_instance_metadata") as get_mock:
            get_mock.return_value = metadata
            instance_id = bootstrap.upsert_local_instance_record("local")
        self.assertIsNotNone(instance_id)
