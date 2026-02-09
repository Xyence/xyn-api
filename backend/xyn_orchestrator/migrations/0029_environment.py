import uuid

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0028_instance_release_state"),
    ]

    operations = [
        migrations.CreateModel(
            name="Environment",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200)),
                ("slug", models.SlugField(max_length=120, unique=True)),
                ("base_domain", models.CharField(blank=True, max_length=200)),
                ("aws_region", models.CharField(blank=True, max_length=50)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "ordering": ["name"],
            },
        ),
        migrations.AddField(
            model_name="releaseplan",
            name="environment",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="release_plans",
                to="xyn_orchestrator.environment",
            ),
        ),
        migrations.AddField(
            model_name="release",
            name="environment",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="releases",
                to="xyn_orchestrator.environment",
            ),
        ),
        migrations.AddField(
            model_name="provisionedinstance",
            name="environment",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="instances",
                to="xyn_orchestrator.environment",
            ),
        ),
    ]
