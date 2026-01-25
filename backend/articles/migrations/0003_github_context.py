from django.db import migrations, models
import django.db.models.deletion
import django.contrib.postgres.search


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0002_articleversion_openaiconfig"),
    ]

    operations = [
        migrations.AddField(
            model_name="openaiconfig",
            name="persistent_context",
            field=models.TextField(blank=True),
        ),
        migrations.CreateModel(
            name="GitHubConfig",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(default="default", max_length=100)),
                ("access_token", models.TextField()),
                ("organization", models.CharField(max_length=200)),
                ("enabled", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="GitHubRepo",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=200)),
                ("full_name", models.CharField(max_length=300, unique=True)),
                ("default_branch", models.CharField(blank=True, max_length=200)),
                ("description", models.TextField(blank=True)),
                ("is_active", models.BooleanField(default=True)),
                ("last_indexed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "config",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="repos", to="articles.githubconfig"),
                ),
            ],
        ),
        migrations.CreateModel(
            name="GitHubRepoChunk",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("path", models.CharField(max_length=500)),
                ("content", models.TextField()),
                ("content_search", django.contrib.postgres.search.SearchVectorField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "repo",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="chunks", to="articles.githubrepo"),
                ),
            ],
            options={
                "indexes": [models.Index(fields=["path"], name="articles_githubrepochunk_path_idx")],
            },
        ),
    ]
