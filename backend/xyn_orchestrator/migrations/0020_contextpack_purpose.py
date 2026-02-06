import django.db.models
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("articles", "0019_registry_run_artifacts"),
    ]

    operations = [
        migrations.AddField(
            model_name="contextpack",
            name="purpose",
            field=django.db.models.CharField(
                choices=[
                    ("any", "Any"),
                    ("planner", "Planner"),
                    ("coder", "Coder"),
                    ("deployer", "Deployer"),
                    ("operator", "Operator"),
                ],
                default="any",
                max_length=20,
            ),
        ),
        migrations.AlterUniqueTogether(
            name="contextpack",
            unique_together={("name", "version", "purpose", "scope", "namespace", "project_key")},
        ),
    ]
