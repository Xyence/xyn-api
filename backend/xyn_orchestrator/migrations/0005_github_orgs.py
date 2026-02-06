from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0004_github_oauth"),
    ]

    operations = [
        migrations.CreateModel(
            name="GitHubOrganization",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("login", models.CharField(max_length=200)),
                ("name", models.CharField(blank=True, max_length=200)),
                ("description", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "config",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="orgs", to="articles.githubconfig"),
                ),
            ],
            options={
                "unique_together": {("config", "login")},
            },
        ),
        migrations.AddField(
            model_name="githubconfig",
            name="organization_ref",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="articles.githuborganization"),
        ),
    ]
