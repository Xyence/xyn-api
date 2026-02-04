import uuid

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0025_dev_task_force_flag"),
    ]

    operations = [
        migrations.CreateModel(
            name="ReleasePlanDeployment",
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
                        related_name="deployments",
                        to="articles.provisionedinstance",
                    ),
                ),
                (
                    "release_plan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="deployments",
                        to="articles.releaseplan",
                    ),
                ),
            ],
        ),
        migrations.AlterUniqueTogether(
            name="releaseplandeployment",
            unique_together={("release_plan", "instance")},
        ),
    ]
