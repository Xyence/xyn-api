from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0059_remove_ems_context_pack"),
    ]

    operations = [
        migrations.AddField(
            model_name="blueprint",
            name="archived_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="blueprint",
            name="deprovisioned_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="blueprint",
            name="deprovision_last_run",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="blueprints_deprovisioned",
                to="xyn_orchestrator.run",
            ),
        ),
        migrations.AddField(
            model_name="blueprint",
            name="status",
            field=models.CharField(
                choices=[
                    ("active", "Active"),
                    ("archived", "Archived"),
                    ("deprovisioning", "Deprovisioning"),
                    ("deprovisioned", "Deprovisioned"),
                ],
                default="active",
                max_length=20,
            ),
        ),
    ]
