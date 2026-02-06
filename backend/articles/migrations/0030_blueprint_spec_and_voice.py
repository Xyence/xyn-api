import uuid

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0029_environment"),
    ]

    operations = [
        migrations.AddField(
            model_name="blueprint",
            name="spec_text",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="blueprint",
            name="metadata_json",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="blueprintdraftsession",
            name="blueprint",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="draft_sessions_source",
                to="articles.blueprint",
            ),
        ),
    ]
