import uuid

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0023_releaseplan_links_and_dev_task_target_instance"),
    ]

    operations = [
        migrations.CreateModel(
            name="RunCommandExecution",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)),
                ("step_name", models.CharField(max_length=120, blank=True)),
                ("command_index", models.PositiveIntegerField(default=0)),
                ("shell", models.CharField(max_length=40, default="sh")),
                ("status", models.CharField(max_length=20, default="pending")),
                ("exit_code", models.IntegerField(null=True, blank=True)),
                ("started_at", models.DateTimeField(null=True, blank=True)),
                ("finished_at", models.DateTimeField(null=True, blank=True)),
                ("ssm_command_id", models.CharField(max_length=120, blank=True)),
                ("stdout", models.TextField(blank=True)),
                ("stderr", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "run",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="command_executions",
                        to="xyn_orchestrator.run",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="ReleasePlanDeployState",
            fields=[
                ("id", models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)),
                ("last_applied_hash", models.CharField(max_length=64, blank=True)),
                ("last_applied_at", models.DateTimeField(null=True, blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "instance",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="deploy_states",
                        to="xyn_orchestrator.provisionedinstance",
                    ),
                ),
                (
                    "release_plan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="deploy_states",
                        to="xyn_orchestrator.releaseplan",
                    ),
                ),
            ],
        ),
        migrations.AlterUniqueTogether(
            name="releaseplandeploystate",
            unique_together={("release_plan", "instance")},
        ),
    ]
