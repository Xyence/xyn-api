from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0077_explainer_multi_agent_ai_config"),
    ]

    operations = [
        migrations.AddField(
            model_name="contextpack",
            name="seeded_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="contextpack",
            name="seeded_by_pack_slug",
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AddField(
            model_name="contextpack",
            name="seeded_content_hash",
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name="contextpack",
            name="seeded_version",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.CreateModel(
            name="SeedPack",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("slug", models.SlugField(max_length=160, unique=True)),
                ("name", models.CharField(max_length=200)),
                ("description", models.TextField(blank=True)),
                ("version", models.CharField(max_length=64)),
                ("scope", models.CharField(choices=[("core", "Core"), ("optional", "Optional")], default="optional", max_length=20)),
                ("namespace", models.CharField(blank=True, max_length=120)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["slug"]},
        ),
        migrations.CreateModel(
            name="SeedApplication",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("applied_at", models.DateTimeField(auto_now_add=True)),
                ("result_summary_json", models.JSONField(default=dict)),
                ("status", models.CharField(choices=[("succeeded", "Succeeded"), ("failed", "Failed")], default="succeeded", max_length=20)),
                ("error_message", models.TextField(blank=True)),
                (
                    "applied_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="seed_applications",
                        to="xyn_orchestrator.useridentity",
                    ),
                ),
                (
                    "seed_pack",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="applications", to="xyn_orchestrator.seedpack"),
                ),
            ],
            options={"ordering": ["-applied_at"]},
        ),
        migrations.CreateModel(
            name="SeedItem",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("entity_type", models.CharField(max_length=60)),
                ("entity_slug", models.CharField(max_length=200)),
                ("entity_unique_key_json", models.JSONField(default=dict)),
                ("payload_json", models.JSONField(default=dict)),
                ("content_hash", models.CharField(max_length=128)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "seed_pack",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="items", to="xyn_orchestrator.seedpack"),
                ),
            ],
            options={"ordering": ["seed_pack__slug", "entity_type", "entity_slug"]},
        ),
        migrations.CreateModel(
            name="SeedApplicationItem",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("action", models.CharField(choices=[("created", "Created"), ("updated", "Updated"), ("unchanged", "Unchanged"), ("skipped", "Skipped"), ("failed", "Failed")], max_length=20)),
                ("target_entity_id", models.UUIDField(blank=True, null=True)),
                ("message", models.TextField(blank=True)),
                (
                    "seed_application",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="items", to="xyn_orchestrator.seedapplication"),
                ),
                (
                    "seed_item",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="application_items", to="xyn_orchestrator.seeditem"),
                ),
            ],
            options={"ordering": ["seed_application__applied_at", "seed_item__entity_type", "seed_item__entity_slug"]},
        ),
        migrations.AddConstraint(
            model_name="seeditem",
            constraint=models.UniqueConstraint(fields=("seed_pack", "entity_type", "entity_slug"), name="uniq_seed_item_per_pack_entity"),
        ),
    ]
