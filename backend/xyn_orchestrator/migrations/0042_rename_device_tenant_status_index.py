from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0041_deployment"),
    ]

    operations = [
        migrations.RenameIndex(
            model_name="device",
            old_name="articles_device_tenant_status_idx",
            new_name="xyn_orchest_tenant__69d1f6_idx",
        )
    ]

