from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0013_blueprint_diff_summary"),
    ]

    operations = [
        migrations.AddField(
            model_name="voicenote",
            name="job_id",
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="job_id",
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="last_error",
            field=models.TextField(blank=True),
        ),
    ]
