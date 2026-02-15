from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0055_blueprintdraftsession_context_resolved_at"),
    ]

    operations = [
        migrations.AlterField(
            model_name="draftsessionrevision",
            name="action",
            field=models.CharField(
                choices=[
                    ("generate", "Generate"),
                    ("revise", "Revise"),
                    ("save", "Save"),
                    ("snapshot", "Snapshot"),
                    ("submit", "Submit"),
                ],
                default="save",
                max_length=20,
            ),
        ),
    ]

