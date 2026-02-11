from django.db import migrations, models


def forwards(apps, schema_editor):
    Release = apps.get_model("xyn_orchestrator", "Release")
    for release in Release.objects.all():
        if release.status == "published":
            release.build_state = "ready"
        else:
            release.build_state = "draft"
        release.save(update_fields=["build_state"])


def backwards(apps, schema_editor):
    Release = apps.get_model("xyn_orchestrator", "Release")
    for release in Release.objects.all():
        release.build_state = "draft"
        release.save(update_fields=["build_state"])


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0044_audit_log"),
    ]

    operations = [
        migrations.AddField(
            model_name="release",
            name="build_state",
            field=models.CharField(
                choices=[
                    ("draft", "Draft"),
                    ("building", "Building"),
                    ("ready", "Ready"),
                    ("failed", "Failed"),
                ],
                default="draft",
                max_length=20,
            ),
        ),
        migrations.RunPython(forwards, backwards),
    ]
