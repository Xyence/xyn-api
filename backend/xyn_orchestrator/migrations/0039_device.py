from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("articles", "0038_brand_profile"),
    ]

    operations = [
        migrations.CreateModel(
            name="Device",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200)),
                ("device_type", models.CharField(max_length=120)),
                ("mgmt_ip", models.CharField(blank=True, max_length=120, null=True)),
                ("status", models.CharField(choices=[("active", "Active"), ("offline", "Offline"), ("unknown", "Unknown")], default="unknown", max_length=20)),
                ("tags", models.JSONField(blank=True, null=True)),
                ("metadata_json", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="devices", to="articles.tenant")),
            ],
            options={"ordering": ["name"], "unique_together": {("tenant", "name")}},
        ),
        migrations.AddIndex(
            model_name="device",
            index=models.Index(fields=["tenant", "status"], name="articles_device_tenant_status_idx"),
        ),
    ]
