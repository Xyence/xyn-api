from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0024_run_command_execution_and_deploy_state"),
    ]

    operations = [
        migrations.AddField(
            model_name="devtask",
            name="force",
            field=models.BooleanField(default=False),
        ),
    ]
