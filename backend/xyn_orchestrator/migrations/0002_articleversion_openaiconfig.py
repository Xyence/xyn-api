from django.db import migrations, models
import django.db.models.deletion
import django_ckeditor_5.fields


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="OpenAIConfig",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(default="default", max_length=100)),
                ("api_key", models.TextField()),
                ("default_model", models.CharField(default="gpt-5.2", max_length=100)),
                (
                    "system_instructions",
                    models.TextField(
                        default=(
                            "You are assisting in drafting technical articles for Xyence, a CTO and "
                            "platform consulting firm. Respond with JSON that includes a title, "
                            "summary, and HTML body suitable for a website article."
                        )
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="ArticleVersion",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("version_number", models.PositiveIntegerField()),
                ("title", models.CharField(max_length=200)),
                ("summary", models.TextField(blank=True)),
                ("body", django_ckeditor_5.fields.CKEditor5Field("body", config_name="default")),
                (
                    "source",
                    models.CharField(choices=[("ai", "AI"), ("manual", "Manual")], default="ai", max_length=20),
                ),
                ("prompt", models.TextField(blank=True)),
                ("model_name", models.CharField(blank=True, max_length=100)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "article",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="versions", to="xyn_orchestrator.article"),
                ),
            ],
            options={
                "ordering": ["-created_at"],
                "unique_together": {("article", "version_number")},
            },
        ),
    ]
