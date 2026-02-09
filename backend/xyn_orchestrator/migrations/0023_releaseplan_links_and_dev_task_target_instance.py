from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0022_dev_task"),
    ]

    operations = [
        migrations.AddField(
            model_name="releaseplan",
            name="blueprint",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="release_plans",
                to="xyn_orchestrator.blueprint",
            ),
        ),
        migrations.AddField(
            model_name="releaseplan",
            name="last_run",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="release_plans",
                to="xyn_orchestrator.run",
            ),
        ),
        migrations.AddField(
            model_name="devtask",
            name="target_instance",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="dev_tasks",
                to="xyn_orchestrator.provisionedinstance",
            ),
        ),
    ]
