from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0088_videorender_outcome_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="workspace",
            name="status",
            field=models.CharField(
                choices=[("active", "Active"), ("deprecated", "Deprecated")],
                default="active",
                max_length=20,
            ),
        ),
    ]

