from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0051_draft_session_defaults_and_sources"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="DraftSessionRevision",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("revision_number", models.PositiveIntegerField()),
                (
                    "action",
                    models.CharField(
                        choices=[("generate", "Generate"), ("revise", "Revise"), ("save", "Save"), ("submit", "Submit")],
                        default="save",
                        max_length=20,
                    ),
                ),
                ("instruction", models.TextField(blank=True)),
                ("draft_json", models.JSONField(blank=True, null=True)),
                ("requirements_summary", models.TextField(blank=True)),
                ("diff_summary", models.TextField(blank=True)),
                ("validation_errors_json", models.JSONField(blank=True, default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="draft_session_revisions_created",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "draft_session",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="revisions",
                        to="xyn_orchestrator.blueprintdraftsession",
                    ),
                ),
            ],
            options={
                "ordering": ["-revision_number", "-created_at"],
                "unique_together": {("draft_session", "revision_number")},
            },
        ),
    ]

