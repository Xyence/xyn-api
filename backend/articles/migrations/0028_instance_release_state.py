from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0027_release_model"),
    ]

    operations = [
        migrations.AddField(
            model_name="provisionedinstance",
            name="desired_release",
            field=models.ForeignKey(
                null=True,
                blank=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="desired_instances",
                to="articles.release",
            ),
        ),
        migrations.AddField(
            model_name="provisionedinstance",
            name="observed_release",
            field=models.ForeignKey(
                null=True,
                blank=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="observed_instances",
                to="articles.release",
            ),
        ),
        migrations.AddField(
            model_name="provisionedinstance",
            name="observed_at",
            field=models.DateTimeField(null=True, blank=True),
        ),
        migrations.AddField(
            model_name="provisionedinstance",
            name="last_deploy_run",
            field=models.ForeignKey(
                null=True,
                blank=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="deploy_runs",
                to="articles.run",
            ),
        ),
        migrations.AddField(
            model_name="provisionedinstance",
            name="health_status",
            field=models.CharField(
                max_length=20,
                default="unknown",
                choices=[
                    ("unknown", "Unknown"),
                    ("healthy", "Healthy"),
                    ("degraded", "Degraded"),
                    ("failed", "Failed"),
                ],
            ),
        ),
    ]
