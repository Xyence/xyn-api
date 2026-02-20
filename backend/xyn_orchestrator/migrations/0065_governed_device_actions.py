from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0064_artifact_slug_field"),
    ]

    operations = [
        migrations.CreateModel(
            name="DraftAction",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("instance_ref", models.CharField(blank=True, default="", max_length=120)),
                (
                    "action_type",
                    models.CharField(
                        choices=[
                            ("device.reboot", "Device Reboot"),
                            ("device.factory_reset", "Device Factory Reset"),
                            ("device.push_config", "Device Push Config"),
                            ("credential_ref.attach", "Credential Ref Attach"),
                            ("adapter.enable", "Adapter Enable"),
                            ("adapter.configure", "Adapter Configure"),
                        ],
                        max_length=120,
                    ),
                ),
                (
                    "action_class",
                    models.CharField(
                        choices=[
                            ("read_only", "Read Only"),
                            ("write_proposed", "Write Proposed"),
                            ("write_execute", "Write Execute"),
                            ("account_security_write", "Account Security Write"),
                        ],
                        max_length=40,
                    ),
                ),
                ("params_json", models.JSONField(blank=True, default=dict)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("draft", "Draft"),
                            ("pending_verification", "Pending Verification"),
                            ("pending_ratification", "Pending Ratification"),
                            ("executing", "Executing"),
                            ("succeeded", "Succeeded"),
                            ("failed", "Failed"),
                            ("canceled", "Canceled"),
                        ],
                        default="draft",
                        max_length=40,
                    ),
                ),
                ("last_error_code", models.CharField(blank=True, default="", max_length=120)),
                ("last_error_message", models.TextField(blank=True, default="")),
                ("provenance_json", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "custodian",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="draft_actions_custodied",
                        to="xyn_orchestrator.useridentity",
                    ),
                ),
                (
                    "device",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="draft_actions",
                        to="xyn_orchestrator.device",
                    ),
                ),
                (
                    "requested_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="draft_actions_requested",
                        to="xyn_orchestrator.useridentity",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="draft_actions",
                        to="xyn_orchestrator.tenant",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(fields=["tenant", "status"], name="xyn_orchest_tenant__2621b1_idx"),
                    models.Index(fields=["device", "created_at"], name="xyn_orchest_device__6b9f25_idx"),
                ],
            },
        ),
        migrations.CreateModel(
            name="ExecutionReceipt",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("executed_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("adapter_key", models.CharField(blank=True, default="", max_length=120)),
                ("request_payload_redacted_json", models.JSONField(blank=True, default=dict)),
                ("response_redacted_json", models.JSONField(blank=True, default=dict)),
                ("outcome", models.CharField(choices=[("success", "Success"), ("failure", "Failure")], max_length=20)),
                ("error_code", models.CharField(blank=True, default="", max_length=120)),
                ("error_message", models.TextField(blank=True, default="")),
                ("logs_ref", models.CharField(blank=True, default="", max_length=300)),
                (
                    "draft_action",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="receipts",
                        to="xyn_orchestrator.draftaction",
                    ),
                ),
                (
                    "executed_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="execution_receipts",
                        to="xyn_orchestrator.useridentity",
                    ),
                ),
            ],
            options={
                "ordering": ["-executed_at"],
            },
        ),
        migrations.CreateModel(
            name="DraftActionEvent",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("event_type", models.CharField(max_length=120)),
                ("from_status", models.CharField(blank=True, default="", max_length=40)),
                ("to_status", models.CharField(blank=True, default="", max_length=40)),
                ("payload_json", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="draft_action_events",
                        to="xyn_orchestrator.useridentity",
                    ),
                ),
                (
                    "draft_action",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="events",
                        to="xyn_orchestrator.draftaction",
                    ),
                ),
            ],
            options={
                "ordering": ["created_at"],
                "indexes": [models.Index(fields=["draft_action", "created_at"], name="xyn_orchest_draft_a_938355_idx")],
            },
        ),
        migrations.CreateModel(
            name="RatificationEvent",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("ratified_at", models.DateTimeField(default=django.utils.timezone.now)),
                (
                    "method",
                    models.CharField(
                        choices=[
                            ("ui_confirm", "UI Confirm"),
                            ("admin_override", "Admin Override"),
                            ("policy_auto", "Policy Auto"),
                        ],
                        default="ui_confirm",
                        max_length=40,
                    ),
                ),
                ("notes", models.TextField(blank=True, default="")),
                (
                    "draft_action",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="ratification_events",
                        to="xyn_orchestrator.draftaction",
                    ),
                ),
                (
                    "ratified_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="ratifications",
                        to="xyn_orchestrator.useridentity",
                    ),
                ),
            ],
            options={
                "ordering": ["-ratified_at"],
            },
        ),
        migrations.CreateModel(
            name="ActionVerifierEvidence",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("verifier_type", models.CharField(max_length=80)),
                (
                    "status",
                    models.CharField(
                        choices=[("required", "Required"), ("satisfied", "Satisfied"), ("failed", "Failed")],
                        default="required",
                        max_length=20,
                    ),
                ),
                ("evidence_json", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "draft_action",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="verifier_evidence",
                        to="xyn_orchestrator.draftaction",
                    ),
                ),
            ],
            options={
                "ordering": ["created_at"],
                "indexes": [models.Index(fields=["draft_action", "verifier_type"], name="xyn_orchest_draft_a_4443de_idx")],
            },
        ),
    ]
