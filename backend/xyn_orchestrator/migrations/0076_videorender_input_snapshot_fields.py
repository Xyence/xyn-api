from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0075_video_explainer_context_pack_traceability"),
    ]

    operations = [
        migrations.AddField(
            model_name="videorender",
            name="input_snapshot_hash",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="videorender",
            name="model_name",
            field=models.CharField(blank=True, max_length=120),
        ),
        migrations.AddField(
            model_name="videorender",
            name="spec_snapshot_hash",
            field=models.CharField(blank=True, max_length=64),
        ),
    ]
