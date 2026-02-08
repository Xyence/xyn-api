from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("articles", "0035_environment_metadata_json"),
    ]

    operations = [
        migrations.CreateModel(
            name="Tenant",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200)),
                ("slug", models.SlugField(max_length=120, unique=True)),
                ("status", models.CharField(choices=[("active", "Active"), ("suspended", "Suspended")], default="active", max_length=20)),
                ("metadata_json", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="Contact",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200)),
                ("email", models.EmailField(blank=True, max_length=254, null=True)),
                ("phone", models.CharField(blank=True, max_length=50, null=True)),
                ("role_title", models.CharField(blank=True, max_length=120, null=True)),
                ("status", models.CharField(choices=[("active", "Active"), ("inactive", "Inactive")], default="active", max_length=20)),
                ("metadata_json", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="contacts", to="articles.tenant")),
            ],
            options={"ordering": ["name"]},
        ),
    ]
