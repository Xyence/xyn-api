import json
import os
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase

from xyn_orchestrator.models import (
    Artifact,
    ArtifactRevision,
    ArtifactType,
    ContextPack,
    RoleBinding,
    UserIdentity,
    Workspace,
)
from xyn_orchestrator.xyn_api import _resolve_dns_record_from_instance, _validate_instance_v1_payload


class InstanceDnsTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username="dns-admin", password="pass", is_staff=True)
        self.client.force_login(self.user)
        self.identity = UserIdentity.objects.create(
            provider="oidc",
            issuer="https://issuer",
            subject="dns-admin",
            email="dns-admin@example.com",
        )
        RoleBinding.objects.create(user_identity=self.identity, scope_kind="platform", role="platform_admin")
        self.workspace, _ = Workspace.objects.get_or_create(slug="platform-builder", defaults={"name": "Platform Builder"})
        session = self.client.session
        session["user_identity_id"] = str(self.identity.id)
        session.save()
        os.environ["XYN_INTENT_ENGINE_V1"] = "1"

        self.instance_type, _ = ArtifactType.objects.get_or_create(
            slug="instance",
            defaults={"name": "Instance", "description": "Instance"},
        )
        self.instance_artifact, created = Artifact.objects.get_or_create(
            workspace=self.workspace,
            slug="xyn-ec2-demo",
            defaults={
                "type": self.instance_type,
                "title": "xyn-ec2-demo",
                "schema_version": "xyn.instance.v1",
                "status": "published",
                "visibility": "team",
            },
        )
        if self.instance_artifact.type_id != self.instance_type.id:
            self.instance_artifact.type = self.instance_type
            self.instance_artifact.save(update_fields=["type", "updated_at"])
        latest = ArtifactRevision.objects.filter(artifact=self.instance_artifact).order_by("-revision_number").first()
        latest_payload = latest.content_json if latest and isinstance(latest.content_json, dict) else {}
        desired_payload = {
            "schema_version": "xyn.instance.v1",
            "name": "xyn-ec2-demo",
            "kind": "ec2",
            "status": "running",
            "network": {"public_ipv4": "54.200.65.160"},
            "notes": {"source": "manual_bootstrap"},
        }
        if created or latest_payload != desired_payload:
            ArtifactRevision.objects.create(
                artifact=self.instance_artifact,
                revision_number=int(getattr(latest, "revision_number", 0) or 0) + 1,
                content_json=desired_payload,
            )

    def tearDown(self):
        os.environ.pop("XYN_INTENT_ENGINE_V1", None)

    def test_instance_v1_validation(self):
        ok_payload = {
            "schema_version": "xyn.instance.v1",
            "name": "demo",
            "kind": "ec2",
            "status": "running",
            "network": {"public_ipv4": "1.2.3.4"},
        }
        self.assertEqual(_validate_instance_v1_payload(ok_payload), [])

        bad_payload = {
            "schema_version": "xyn.instance.v1",
            "name": "demo",
            "kind": "ec2",
            "status": "running",
            "network": {},
        }
        self.assertTrue(_validate_instance_v1_payload(bad_payload))

    def test_dns_record_decision_prefers_hostname(self):
        record_type, record_value = _resolve_dns_record_from_instance(
            {"network": {"public_ipv4": "1.2.3.4", "public_hostname": "demo.example.com"}}
        )
        self.assertEqual(record_type, "CNAME")
        self.assertEqual(record_value, "demo.example.com")

        record_type, record_value = _resolve_dns_record_from_instance(
            {"network": {"public_ipv4": "1.2.3.4"}}
        )
        self.assertEqual(record_type, "A")
        self.assertEqual(record_value, "1.2.3.4")

    @mock.patch("xyn_orchestrator.xyn_api.Route53DnsProvider.upsert_record")
    def test_install_xyn_instance_route53_uses_instance_and_records_dns_action(self, mock_upsert):
        module_type, _ = ArtifactType.objects.get_or_create(slug="module", defaults={"name": "Module"})
        Artifact.objects.get_or_create(
            workspace=self.workspace,
            slug="xyn-api",
            defaults={"type": module_type, "title": "xyn-api", "status": "published", "visibility": "team"},
        )
        Artifact.objects.get_or_create(
            workspace=self.workspace,
            slug="xyn-ui",
            defaults={"type": module_type, "title": "xyn-ui", "status": "published", "visibility": "team"},
        )
        credentials_pack = ContextPack.objects.create(
            name="aws-route53-demo-creds",
            purpose="operator",
            scope="global",
            version="1.0.0",
            is_active=True,
            content_markdown=json.dumps(
                {
                    "aws": {
                        "access_key_id": "demo-key",
                        "secret_access_key": "demo-secret",
                        "region": "us-west-2",
                    }
                }
            ),
        )
        mock_upsert.return_value = {"change_id": "C123", "status": "PENDING"}

        resolve_response = self.client.post(
            "/xyn/api/xyn/intent/resolve",
            data=json.dumps({"message": "install xyn instance for ACME Co fqdn ems.xyence.io route53", "context": {"workspace_id": str(self.workspace.id)}}),
            content_type="application/json",
        )
        self.assertEqual(resolve_response.status_code, 200)
        draft_payload = resolve_response.json().get("draft_payload") or {}
        draft_payload["dns_provider"] = {
            "kind": "route53",
            "hosted_zone_id": "Z123456",
            "region": "us-west-2",
            "credentials_ref": {"context_pack_id": str(credentials_pack.id)},
        }
        draft_payload["dns_mode"] = "route53"
        draft_payload["dns"] = {"enabled": True, "ttl": 60}

        apply_response = self.client.post(
            "/xyn/api/xyn/intent/apply",
            data=json.dumps(
                {
                    "action_type": "CreateDraft",
                    "artifact_type": "Workspace",
                    "payload": draft_payload,
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(apply_response.status_code, 200, apply_response.content.decode())
        payload = apply_response.json()
        dns_action = ((payload.get("result") or {}).get("dns_action") or {})
        self.assertEqual(dns_action.get("status"), "succeeded")
        self.assertEqual(dns_action.get("record_type"), "A")
        self.assertEqual(dns_action.get("record_value"), "54.200.65.160")
        mock_upsert.assert_called_once()
