import json
import tempfile
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings

from xyn_orchestrator.models import PlatformConfigDocument, Report, ReportAttachment, RoleBinding, SecretRef, SecretStore, UserIdentity
from xyn_orchestrator.notifications.registry import resolve_secret_ref_value
from xyn_orchestrator.xyn_api import _validate_schema_payload


class ReportsApiTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="reporter",
            email="reporter@xyence.io",
            password="x",
            is_staff=True,
            is_active=True,
        )
        self.identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer.example.com",
            subject="reporter",
            email="reporter@xyence.io",
        )
        RoleBinding.objects.create(user_identity=self.identity, scope_kind="platform", role="platform_admin")
        self.client.force_login(self.user)
        session = self.client.session
        session["user_identity_id"] = str(self.identity.id)
        session.save()

    def _platform_config(self, base_path: str):
        return {
            "storage": {
                "primary": {"type": "local", "name": "local"},
                "providers": [
                    {"name": "local", "type": "local", "local": {"base_path": base_path}}
                ],
            },
            "notifications": {
                "enabled": True,
                "channels": [],
            },
        }

    def test_schema_validation_for_report_and_platform_config(self):
        report_ok = {
            "type": "bug",
            "title": "Broken deploy button",
            "description": "Clicking deploy does nothing",
            "priority": "p1",
            "context": {"url": "https://xyence.io/app/releases", "route": "/app/releases"},
        }
        report_bad = {
            "type": "incident",
            "title": "",
            "description": "",
        }
        cfg_ok = self._platform_config("/tmp/xyn-uploads")
        cfg_bad = {"storage": {"primary": {"type": "s3"}}, "notifications": {}}

        self.assertEqual(_validate_schema_payload(report_ok, "report.v1.schema.json"), [])
        self.assertTrue(_validate_schema_payload(report_bad, "report.v1.schema.json"))
        self.assertEqual(_validate_schema_payload(cfg_ok, "platform_config.v1.schema.json"), [])
        self.assertTrue(_validate_schema_payload(cfg_bad, "platform_config.v1.schema.json"))

    def test_report_creation_with_two_attachments_local_provider(self):
        with tempfile.TemporaryDirectory() as tempdir:
            PlatformConfigDocument.objects.create(version=1, config_json=self._platform_config(tempdir), created_by=self.user)
            payload = {
                "type": "bug",
                "title": "Map edge labels overlap",
                "description": "Edge labels overlap on dense graphs",
                "priority": "p2",
                "tags": ["map", "ui"],
                "context": {"url": "https://xyence.io/app/map", "route": "/app/map"},
            }
            image1 = SimpleUploadedFile("shot1.png", b"png-data-1", content_type="image/png")
            image2 = SimpleUploadedFile("shot2.png", b"png-data-2", content_type="image/png")
            response = self.client.post(
                "/api/v1/reports",
                data={"payload": json.dumps(payload), "attachments": [image1, image2]},
            )
            self.assertEqual(response.status_code, 200)
            body = response.json()
            self.assertEqual(body["type"], "bug")
            self.assertEqual(len(body.get("attachments", [])), 2)

            report = Report.objects.get(id=body["id"])
            self.assertEqual(report.title, "Map edge labels overlap")
            self.assertEqual(ReportAttachment.objects.filter(report=report).count(), 2)
            for attachment in ReportAttachment.objects.filter(report=report):
                self.assertEqual(attachment.storage_provider, "local")
                self.assertTrue(Path(attachment.storage_path).exists())

    @mock.patch("xyn_orchestrator.xyn_api.NotifierRegistry.notify_report_created")
    def test_notifier_called_on_report_create(self, notify_mock):
        with tempfile.TemporaryDirectory() as tempdir:
            PlatformConfigDocument.objects.create(version=1, config_json=self._platform_config(tempdir), created_by=self.user)
            notify_mock.return_value = []
            payload = {
                "type": "feature",
                "title": "Add bulk export",
                "description": "Need csv export",
                "priority": "p3",
            }
            response = self.client.post(
                "/api/v1/reports",
                data={"payload": json.dumps(payload)},
            )
            self.assertEqual(response.status_code, 200)
            self.assertTrue(notify_mock.called)

    @mock.patch("xyn_orchestrator.notifications.registry.resolve_secret_ref")
    def test_secret_ref_resolution_path_for_discord_webhook(self, resolve_secret_mock):
        resolve_secret_mock.return_value = "https://discord.example/webhook"
        store = SecretStore.objects.create(
            name="default-aws",
            kind="aws_secrets_manager",
            is_default=True,
            config_json={"aws_region": "us-east-1", "name_prefix": "/xyn"},
        )
        secret_ref = SecretRef.objects.create(
            name="discord/default/webhook",
            scope_kind="platform",
            scope_id=None,
            store=store,
            external_ref="arn:aws:secretsmanager:us-east-1:123:secret:xyn/discord",
            type="secrets_manager",
            created_by=self.user,
        )
        value = resolve_secret_ref_value(f"secret_ref:{secret_ref.id}")
        self.assertEqual(value, "https://discord.example/webhook")
        resolve_secret_mock.assert_called_once_with(
            {"type": "aws.secrets_manager", "ref": "arn:aws:secretsmanager:us-east-1:123:secret:xyn/discord"}
        )
