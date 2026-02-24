from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0074_artifact_video_explainer_and_render"),
    ]

    operations = [
        migrations.AddField(
            model_name="artifact",
            name="video_context_pack",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="video_articles",
                to="xyn_orchestrator.contextpack",
            ),
        ),
        migrations.AddField(
            model_name="videorender",
            name="context_pack",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="video_renders",
                to="xyn_orchestrator.contextpack",
            ),
        ),
        migrations.AddField(
            model_name="videorender",
            name="context_pack_hash",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="videorender",
            name="context_pack_updated_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="videorender",
            name="context_pack_version",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AlterField(
            model_name="contextpack",
            name="purpose",
            field=models.CharField(
                choices=[
                    ("any", "Any"),
                    ("planner", "Planner"),
                    ("coder", "Coder"),
                    ("deployer", "Deployer"),
                    ("operator", "Operator"),
                    ("video_explainer", "Video Explainer"),
                ],
                default="any",
                max_length=20,
            ),
        ),
    ]
