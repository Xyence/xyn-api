from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("articles", "0037_tenant_membership"),
    ]

    operations = [
        migrations.CreateModel(
            name="BrandProfile",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("display_name", models.CharField(blank=True, max_length=200, null=True)),
                ("logo_url", models.CharField(blank=True, max_length=500, null=True)),
                ("primary_color", models.CharField(blank=True, max_length=40, null=True)),
                ("secondary_color", models.CharField(blank=True, max_length=40, null=True)),
                ("theme_json", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("tenant", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="brand_profile", to="articles.tenant")),
            ],
            options={"ordering": ["tenant__name"]},
        ),
    ]
