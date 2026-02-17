from django.db import migrations


def remove_ems_context_pack(apps, schema_editor):
    ContextPack = apps.get_model("xyn_orchestrator", "ContextPack")
    ContextPack.objects.filter(name="ems-platform-blueprint").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0058_blueprint_repo_slug"),
    ]

    operations = [
        migrations.RunPython(remove_ems_context_pack, migrations.RunPython.noop),
    ]
