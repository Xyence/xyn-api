from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("articles", "0020_contextpack_purpose"),
    ]

    operations = [
        migrations.AddField(
            model_name="run",
            name="context_pack_refs_json",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="run",
            name="context_hash",
            field=models.CharField(blank=True, max_length=64),
        ),
    ]
