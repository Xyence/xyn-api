from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0039_device"),
    ]

    operations = [
        migrations.AlterField(
            model_name="provisionedinstance",
            name="instance_id",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="provisionedinstance",
            name="runtime_substrate",
            field=models.CharField(default="local", max_length=20),
        ),
        migrations.AddField(
            model_name="provisionedinstance",
            name="last_seen_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
