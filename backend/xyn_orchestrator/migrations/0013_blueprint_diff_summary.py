from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0012_alter_blueprintrevision_id_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="diff_summary",
            field=models.TextField(blank=True),
        ),
    ]
