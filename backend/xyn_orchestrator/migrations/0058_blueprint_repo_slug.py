from django.db import migrations, models
from django.utils.text import slugify


def _populate_repo_slug(apps, schema_editor):
    Blueprint = apps.get_model("xyn_orchestrator", "Blueprint")
    for blueprint in Blueprint.objects.all():
        if blueprint.repo_slug:
            continue
        value = (slugify(getattr(blueprint, "name", "") or "") or "blueprint")[:120]
        blueprint.repo_slug = value or "blueprint"
        blueprint.save(update_fields=["repo_slug"])


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0057_blueprintdraftsession_metadata_json"),
    ]

    operations = [
        migrations.AddField(
            model_name="blueprint",
            name="repo_slug",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.RunPython(_populate_repo_slug, migrations.RunPython.noop),
    ]

