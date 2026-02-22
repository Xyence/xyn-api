from django.db import migrations, models
import django.db.models.deletion
import uuid


def forwards(apps, schema_editor):
    ArtifactType = apps.get_model("xyn_orchestrator", "ArtifactType")
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")
    ArticleCategory = apps.get_model("xyn_orchestrator", "ArticleCategory")
    PublishBinding = apps.get_model("xyn_orchestrator", "PublishBinding")

    category_defaults = [
        ("guide", "Guide", "Guides and in-app documentation", True),
        ("web", "Web", "Public website articles", True),
        ("core-concepts", "Core Concepts", "Core concept guides", True),
        ("release-note", "Release Note", "Release note updates", True),
        ("internal", "Internal", "Internal-only content", True),
        ("tutorial", "Tutorial", "Tutorial and walkthrough content", True),
    ]
    categories_by_slug = {}
    for slug, name, description, enabled in category_defaults:
        category, _ = ArticleCategory.objects.get_or_create(
            slug=slug,
            defaults={"name": name, "description": description, "enabled": enabled},
        )
        categories_by_slug[slug] = category

    article_type = ArtifactType.objects.filter(slug="article").first()
    if article_type:
        for artifact in Artifact.objects.filter(type=article_type):
            scope = dict(getattr(artifact, "scope_json", {}) or {})
            legacy_category = str(scope.get("category") or "").strip().lower()
            if not legacy_category:
                legacy_category = "web"
            category = categories_by_slug.get(legacy_category)
            if category is None:
                category, _ = ArticleCategory.objects.get_or_create(
                    slug=legacy_category,
                    defaults={
                        "name": legacy_category.replace("-", " ").title(),
                        "description": "Migrated legacy category",
                        "enabled": True,
                    },
                )
                categories_by_slug[legacy_category] = category
            artifact.article_category_id = category.id
            if scope.get("category") != category.slug:
                scope["category"] = category.slug
                artifact.scope_json = scope
                artifact.save(update_fields=["article_category", "scope_json", "updated_at"])
            else:
                artifact.save(update_fields=["article_category", "updated_at"])

            route_bindings = scope.get("route_bindings") if isinstance(scope.get("route_bindings"), list) else []
            for route in route_bindings:
                value = str(route or "").strip()
                if not value:
                    continue
                PublishBinding.objects.get_or_create(
                    scope_type="article",
                    scope_id=artifact.id,
                    target_type="xyn_ui_route",
                    target_value=value,
                    defaults={"label": "Route", "enabled": True},
                )

    guide_category = ArticleCategory.objects.filter(slug="guide").first()
    if guide_category:
        PublishBinding.objects.get_or_create(
            scope_type="category",
            scope_id=guide_category.id,
            target_type="xyn_ui_route",
            target_value="/app/guides",
            defaults={"label": "Guides", "enabled": True},
        )

    web_category = ArticleCategory.objects.filter(slug="web").first()
    if web_category:
        PublishBinding.objects.get_or_create(
            scope_type="category",
            scope_id=web_category.id,
            target_type="public_web_path",
            target_value="/articles",
            defaults={"label": "Public Website", "enabled": True},
        )


def backwards(apps, schema_editor):
    PublishBinding = apps.get_model("xyn_orchestrator", "PublishBinding")
    ArticleCategory = apps.get_model("xyn_orchestrator", "ArticleCategory")
    ArtifactType = apps.get_model("xyn_orchestrator", "ArtifactType")
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")

    article_type = ArtifactType.objects.filter(slug="article").first()
    if article_type:
        Artifact.objects.filter(type=article_type).update(article_category=None)
    PublishBinding.objects.all().delete()
    ArticleCategory.objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0072_agentpurpose_status"),
    ]

    operations = [
        migrations.CreateModel(
            name="ArticleCategory",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("slug", models.SlugField(max_length=120, unique=True)),
                ("name", models.CharField(max_length=200)),
                ("description", models.TextField(blank=True)),
                ("enabled", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.AddField(
            model_name="artifact",
            name="article_category",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="artifacts",
                to="xyn_orchestrator.articlecategory",
            ),
        ),
        migrations.CreateModel(
            name="PublishBinding",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("scope_type", models.CharField(choices=[("category", "Category"), ("article", "Article")], max_length=20)),
                ("scope_id", models.UUIDField()),
                (
                    "target_type",
                    models.CharField(
                        choices=[("xyn_ui_route", "Xyn UI Route"), ("public_web_path", "Public Web Path"), ("external_url", "External URL")],
                        max_length=30,
                    ),
                ),
                ("target_value", models.CharField(max_length=500)),
                ("label", models.CharField(max_length=200)),
                ("enabled", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["label", "target_value"]},
        ),
        migrations.AddConstraint(
            model_name="publishbinding",
            constraint=models.UniqueConstraint(
                fields=("scope_type", "scope_id", "target_type", "target_value"),
                name="uniq_publish_binding_scope_target",
            ),
        ),
        migrations.RunPython(forwards, backwards),
    ]
