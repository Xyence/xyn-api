from django.db import migrations, models


def forwards(apps, schema_editor):
    AgentPurpose = apps.get_model("xyn_orchestrator", "AgentPurpose")
    for purpose in AgentPurpose.objects.all():
        purpose.status = "active" if bool(getattr(purpose, "enabled", True)) else "deprecated"
        purpose.save(update_fields=["status"])


def backwards(apps, schema_editor):
    AgentPurpose = apps.get_model("xyn_orchestrator", "AgentPurpose")
    for purpose in AgentPurpose.objects.all():
        purpose.enabled = str(getattr(purpose, "status", "active")) != "deprecated"
        purpose.save(update_fields=["enabled"])


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0071_rename_agentpurpose_system_prompt_to_preamble"),
    ]

    operations = [
        migrations.AddField(
            model_name="agentpurpose",
            name="status",
            field=models.CharField(
                choices=[("active", "Active"), ("deprecated", "Deprecated")],
                default="active",
                max_length=20,
            ),
        ),
        migrations.RunPython(forwards, backwards),
    ]

