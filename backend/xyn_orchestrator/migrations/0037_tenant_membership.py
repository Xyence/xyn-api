from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0036_tenant_contact"),
    ]

    operations = [
        migrations.CreateModel(
            name="TenantMembership",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("role", models.CharField(choices=[("tenant_admin", "Tenant Admin"), ("tenant_operator", "Tenant Operator"), ("tenant_viewer", "Tenant Viewer")], default="tenant_viewer", max_length=40)),
                ("status", models.CharField(choices=[("active", "Active"), ("inactive", "Inactive")], default="active", max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="memberships", to="xyn_orchestrator.tenant")),
                ("user_identity", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="memberships", to="xyn_orchestrator.useridentity")),
            ],
            options={"ordering": ["tenant__name"], "unique_together": {("tenant", "user_identity")}},
        ),
    ]
