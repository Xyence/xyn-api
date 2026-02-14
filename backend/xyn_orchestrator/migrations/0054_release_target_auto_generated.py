from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0053_blueprintdraftsession_initial_prompt_locked"),
    ]

    operations = [
        migrations.AddField(
            model_name="releasetarget",
            name="auto_generated",
            field=models.BooleanField(default=False),
        ),
        migrations.AddConstraint(
            model_name="releasetarget",
            constraint=models.UniqueConstraint(
                condition=models.Q(auto_generated=True),
                fields=("blueprint", "environment"),
                name="uniq_auto_release_target_per_bp_env",
            ),
        ),
    ]
