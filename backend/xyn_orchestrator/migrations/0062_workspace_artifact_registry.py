from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0061_identity_provider_group_role_mapping"),
    ]

    operations = [
        migrations.CreateModel(
            name="Workspace",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("slug", models.SlugField(max_length=120, unique=True)),
                ("name", models.CharField(max_length=200)),
                ("description", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="ArtifactType",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("slug", models.SlugField(max_length=120, unique=True)),
                ("name", models.CharField(max_length=200)),
                ("description", models.TextField(blank=True)),
                ("icon", models.CharField(blank=True, max_length=120)),
                ("schema_json", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="Artifact",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("draft", "Draft"),
                            ("reviewed", "Reviewed"),
                            ("ratified", "Ratified"),
                            ("published", "Published"),
                            ("deprecated", "Deprecated"),
                        ],
                        default="draft",
                        max_length=30,
                    ),
                ),
                ("title", models.CharField(max_length=300)),
                ("version", models.PositiveIntegerField(default=1)),
                ("lineage_json", models.JSONField(blank=True, null=True)),
                ("ratified_at", models.DateTimeField(blank=True, null=True)),
                ("published_at", models.DateTimeField(blank=True, null=True)),
                ("visibility", models.CharField(default="private", max_length=30)),
                ("verifiers_required_json", models.JSONField(blank=True, default=list)),
                ("verifiers_satisfied_json", models.JSONField(blank=True, default=list)),
                ("provenance_json", models.JSONField(blank=True, default=dict)),
                ("scope_json", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "author",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="artifacts_authored",
                        to="xyn_orchestrator.useridentity",
                    ),
                ),
                (
                    "custodian",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="artifacts_custodied",
                        to="xyn_orchestrator.useridentity",
                    ),
                ),
                (
                    "ratified_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="artifacts_ratified",
                        to="xyn_orchestrator.useridentity",
                    ),
                ),
                (
                    "type",
                    models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="artifacts", to="xyn_orchestrator.artifacttype"),
                ),
                (
                    "workspace",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="artifacts", to="xyn_orchestrator.workspace"),
                ),
            ],
            options={"ordering": ["-published_at", "-updated_at", "-created_at"]},
        ),
        migrations.CreateModel(
            name="ArtifactComment",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("body", models.TextField()),
                ("status", models.CharField(choices=[("visible", "Visible"), ("hidden", "Hidden"), ("deleted", "Deleted")], default="visible", max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "artifact",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="comments", to="xyn_orchestrator.artifact"),
                ),
                (
                    "parent_comment",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="replies", to="xyn_orchestrator.artifactcomment"),
                ),
                (
                    "user",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="artifact_comments", to="xyn_orchestrator.useridentity"),
                ),
            ],
            options={"ordering": ["created_at"]},
        ),
        migrations.CreateModel(
            name="ArtifactEvent",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("event_type", models.CharField(max_length=120)),
                ("payload_json", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "actor",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="artifact_events", to="xyn_orchestrator.useridentity"),
                ),
                (
                    "artifact",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="events", to="xyn_orchestrator.artifact"),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="ArtifactLink",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("link_type", models.CharField(max_length=120)),
                (
                    "from_artifact",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="links_from", to="xyn_orchestrator.artifact"),
                ),
                (
                    "to_artifact",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="links_to", to="xyn_orchestrator.artifact"),
                ),
            ],
            options={"unique_together": {("from_artifact", "to_artifact", "link_type")}},
        ),
        migrations.CreateModel(
            name="ArtifactReaction",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("value", models.CharField(choices=[("endorse", "Endorse"), ("oppose", "Oppose"), ("neutral", "Neutral")], max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "artifact",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="reactions", to="xyn_orchestrator.artifact"),
                ),
                (
                    "user",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="artifact_reactions", to="xyn_orchestrator.useridentity"),
                ),
            ],
            options={"unique_together": {("artifact", "user")}},
        ),
        migrations.CreateModel(
            name="ArtifactRevision",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("revision_number", models.PositiveIntegerField()),
                ("content_json", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "artifact",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="revisions", to="xyn_orchestrator.artifact"),
                ),
                (
                    "created_by",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="artifact_revisions_created", to="xyn_orchestrator.useridentity"),
                ),
            ],
            options={"ordering": ["-revision_number"], "unique_together": {("artifact", "revision_number")}},
        ),
        migrations.CreateModel(
            name="WorkspaceMembership",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                (
                    "role",
                    models.CharField(
                        choices=[
                            ("reader", "Reader"),
                            ("contributor", "Contributor"),
                            ("publisher", "Publisher"),
                            ("moderator", "Moderator"),
                            ("admin", "Admin"),
                        ],
                        default="reader",
                        max_length=40,
                    ),
                ),
                ("termination_authority", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "user_identity",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="workspace_memberships", to="xyn_orchestrator.useridentity"),
                ),
                (
                    "workspace",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="memberships", to="xyn_orchestrator.workspace"),
                ),
            ],
            options={"ordering": ["workspace__name", "user_identity__email"], "unique_together": {("workspace", "user_identity")}},
        ),
        migrations.CreateModel(
            name="ArtifactExternalRef",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("system", models.CharField(default="django", max_length=60)),
                ("external_id", models.CharField(max_length=120)),
                ("slug_path", models.CharField(blank=True, max_length=240)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "artifact",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="external_refs", to="xyn_orchestrator.artifact"),
                ),
            ],
            options={"unique_together": {("system", "external_id")}},
        ),
        migrations.AddConstraint(
            model_name="artifactexternalref",
            constraint=models.UniqueConstraint(
                condition=~models.Q(slug_path=""), fields=("system", "slug_path"), name="uniq_artifact_extref_slug"
            ),
        ),
    ]
