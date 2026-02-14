from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0052_draft_session_revision"),
    ]

    operations = [
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="initial_prompt_locked",
            field=models.BooleanField(default=False),
        ),
    ]

