# Generated manually for ledger event support.

import django.db.models.deletion
import uuid
from django.db import migrations, models
from django.db.models import Q


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0081_unified_artifact_links"),
    ]

    operations = [
        migrations.CreateModel(
            name="LedgerEvent",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                (
                    "action",
                    models.CharField(
                        choices=[
                            ("artifact.create", "Artifact Create"),
                            ("artifact.update", "Artifact Update"),
                            ("artifact.canonize", "Artifact Canonize"),
                            ("artifact.deprecate", "Artifact Deprecate"),
                            ("artifact.archive", "Artifact Archive"),
                        ],
                        max_length=40,
                    ),
                ),
                ("artifact_type", models.CharField(blank=True, default="", max_length=80)),
                ("artifact_state", models.CharField(blank=True, default="", max_length=20)),
                ("summary", models.CharField(blank=True, default="", max_length=280)),
                ("metadata_json", models.JSONField(blank=True, default=dict)),
                ("dedupe_key", models.CharField(blank=True, default="", max_length=320)),
                ("source_ref_type", models.CharField(blank=True, default="", max_length=80)),
                ("source_ref_id", models.CharField(blank=True, default="", max_length=120)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "actor_user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="ledger_events",
                        to="xyn_orchestrator.useridentity",
                    ),
                ),
                (
                    "artifact",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="ledger_events",
                        to="xyn_orchestrator.artifact",
                    ),
                ),
                (
                    "lineage_root",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="ledger_lineage_events",
                        to="xyn_orchestrator.artifact",
                    ),
                ),
                (
                    "parent_artifact",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="ledger_child_events",
                        to="xyn_orchestrator.artifact",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="ledgerevent",
            constraint=models.UniqueConstraint(
                condition=~Q(dedupe_key=""),
                fields=("dedupe_key",),
                name="uniq_ledger_event_dedupe_key",
            ),
        ),
    ]

