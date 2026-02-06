from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("articles", "0028_instance_release_state"),
    ]

    operations = [
        migrations.AddField(
            model_name="devtask",
            name="work_item_id",
            field=models.CharField(blank=True, max_length=120),
        ),
    ]
