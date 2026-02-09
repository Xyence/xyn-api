from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0042_rename_device_tenant_status_index"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="release",
            name="environment",
        ),
    ]

