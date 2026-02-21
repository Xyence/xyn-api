from django.core.validators import MaxLengthValidator
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0070_agentdefinition_default_assistant"),
    ]

    operations = [
        migrations.RenameField(
            model_name="agentpurpose",
            old_name="system_prompt_markdown",
            new_name="preamble",
        ),
        migrations.AlterField(
            model_name="agentpurpose",
            name="preamble",
            field=models.TextField(blank=True, validators=[MaxLengthValidator(1000)]),
        ),
    ]

