from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0010_remove_github_models"),
    ]

    operations = [
        migrations.CreateModel(
            name="Blueprint",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=120)),
                ("namespace", models.CharField(default="core", max_length=120)),
                ("description", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="blueprints_created", to=settings.AUTH_USER_MODEL)),
                ("updated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="blueprints_updated", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "unique_together": {("name", "namespace")},
            },
        ),
        migrations.CreateModel(
            name="BlueprintDraftSession",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200)),
                ("status", models.CharField(choices=[("drafting", "Drafting"), ("ready", "Ready"), ("ready_with_errors", "Ready with errors"), ("published", "Published"), ("archived", "Archived")], default="drafting", max_length=30)),
                ("current_draft_json", models.JSONField(blank=True, null=True)),
                ("requirements_summary", models.TextField(blank=True)),
                ("validation_errors_json", models.JSONField(blank=True, null=True)),
                ("suggested_fixes_json", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="draft_sessions_created", to=settings.AUTH_USER_MODEL)),
                ("linked_blueprint", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="draft_sessions", to="articles.blueprint")),
                ("updated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="draft_sessions_updated", to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name="BlueprintInstance",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("revision", models.PositiveIntegerField()),
                ("release_id", models.CharField(blank=True, max_length=200)),
                ("status", models.CharField(choices=[("pending", "Pending"), ("planned", "Planned"), ("applied", "Applied"), ("failed", "Failed")], default="pending", max_length=20)),
                ("plan_id", models.CharField(blank=True, max_length=100)),
                ("operation_id", models.CharField(blank=True, max_length=100)),
                ("error", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("blueprint", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="instances", to="articles.blueprint")),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="blueprint_instances_created", to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name="BlueprintRevision",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("revision", models.PositiveIntegerField()),
                ("spec_json", models.JSONField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("blueprint", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="revisions", to="articles.blueprint")),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="blueprint_revisions_created", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "ordering": ["-revision"],
                "unique_together": {("blueprint", "revision")},
            },
        ),
        migrations.CreateModel(
            name="VoiceNote",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("title", models.CharField(blank=True, max_length=200)),
                ("audio_file", models.FileField(upload_to="voice_notes/")),
                ("mime_type", models.CharField(blank=True, max_length=100)),
                ("duration_ms", models.PositiveIntegerField(blank=True, null=True)),
                ("language_code", models.CharField(default="en-US", max_length=20)),
                ("status", models.CharField(choices=[("uploaded", "Uploaded"), ("transcribing", "Transcribing"), ("transcribed", "Transcribed"), ("drafting", "Drafting"), ("ready", "Ready"), ("failed", "Failed")], default="uploaded", max_length=20)),
                ("error", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="voice_notes", to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name="DraftSessionVoiceNote",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("ordering", models.PositiveIntegerField(default=0)),
                ("draft_session", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="articles.blueprintdraftsession")),
                ("voice_note", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="articles.voicenote")),
            ],
            options={
                "ordering": ["ordering"],
                "unique_together": {("draft_session", "voice_note")},
            },
        ),
        migrations.CreateModel(
            name="VoiceTranscript",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("provider", models.CharField(choices=[("google_stt", "Google Speech-to-Text"), ("stub", "Stub")], default="stub", max_length=50)),
                ("transcript_text", models.TextField()),
                ("confidence", models.FloatField(blank=True, null=True)),
                ("raw_response_json", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("voice_note", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="transcript", to="articles.voicenote")),
            ],
        ),
    ]
