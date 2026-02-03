import uuid

from django.db import models
from django.db.models import Max
from django.utils import timezone
from django.utils.text import slugify
from django_ckeditor_5.fields import CKEditor5Field


class Article(models.Model):
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("published", "Published"),
    ]

    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=220, unique=True, blank=True)
    summary = models.TextField(blank=True)
    body = CKEditor5Field("body", config_name="default")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")
    published_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-published_at", "-created_at"]

    def __str__(self) -> str:
        return self.title

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title)[:220]
        if self.status == "published" and self.published_at is None:
            self.published_at = timezone.now()
        super().save(*args, **kwargs)

    def create_version_snapshot(self, source: str = "manual") -> "ArticleVersion":
        return ArticleVersion.objects.create(
            article=self,
            title=self.title,
            summary=self.summary,
            body=self.body,
            source=source,
        )

    def create_version_if_changed(self, source: str = "manual") -> bool:
        latest = (
            ArticleVersion.objects.filter(article=self)
            .order_by("-version_number")
            .first()
        )
        if not latest:
            self.create_version_snapshot(source=source)
            return True
        if (
            latest.title != self.title
            or latest.summary != self.summary
            or latest.body != self.body
        ):
            self.create_version_snapshot(source=source)
            return True
        return False


class ArticleVersion(models.Model):
    SOURCE_CHOICES = [
        ("ai", "AI"),
        ("manual", "Manual"),
    ]

    article = models.ForeignKey(Article, related_name="versions", on_delete=models.CASCADE)
    version_number = models.PositiveIntegerField()
    title = models.CharField(max_length=200)
    summary = models.TextField(blank=True)
    body = CKEditor5Field("body", config_name="default")
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default="ai")
    prompt = models.TextField(blank=True)
    model_name = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        unique_together = ("article", "version_number")

    def __str__(self) -> str:
        return f"{self.article.title} v{self.version_number}"

    def save(self, *args, **kwargs):
        if not self.version_number:
            latest = (
                ArticleVersion.objects.filter(article=self.article)
                .aggregate(max_version=Max("version_number"))
                .get("max_version")
            )
            self.version_number = (latest or 0) + 1
        super().save(*args, **kwargs)


class OpenAIConfig(models.Model):
    name = models.CharField(max_length=100, default="default")
    api_key = models.TextField()
    default_model = models.CharField(max_length=100, default="gpt-5.2")
    persistent_context = models.TextField(blank=True)
    system_instructions = models.TextField(
        default=(
            "You are assisting in drafting technical articles for Xyence, a CTO and "
            "platform consulting firm. Output a JSON object with a title, summary, "
            "and HTML body suitable for a website article. Treat the response as a "
            "draft artifact that will be versioned in a CMS."
        )
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"OpenAI Config ({self.name})"


class VoiceNote(models.Model):
    STATUS_CHOICES = [
        ("uploaded", "Uploaded"),
        ("queued", "Queued"),
        ("transcribing", "Transcribing"),
        ("transcribed", "Transcribed"),
        ("drafting", "Drafting"),
        ("ready", "Ready"),
        ("failed", "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200, blank=True)
    audio_file = models.FileField(upload_to="voice_notes/")
    mime_type = models.CharField(max_length=100, blank=True)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    language_code = models.CharField(max_length=20, default="en-US")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="uploaded")
    job_id = models.CharField(max_length=100, blank=True)
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="voice_notes"
    )

    def __str__(self) -> str:
        return self.title or f"Voice note {self.id}"


class VoiceTranscript(models.Model):
    PROVIDER_CHOICES = [
        ("google_stt", "Google Speech-to-Text"),
        ("stub", "Stub"),
    ]

    voice_note = models.OneToOneField(VoiceNote, on_delete=models.CASCADE, related_name="transcript")
    provider = models.CharField(max_length=50, choices=PROVIDER_CHOICES, default="stub")
    transcript_text = models.TextField()
    confidence = models.FloatField(null=True, blank=True)
    raw_response_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"Transcript for {self.voice_note_id}"


class Blueprint(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    namespace = models.CharField(max_length=120, default="core")
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="blueprints_created"
    )
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="blueprints_updated"
    )

    class Meta:
        unique_together = ("name", "namespace")

    def __str__(self) -> str:
        return f"{self.namespace}.{self.name}"


class BlueprintRevision(models.Model):
    blueprint = models.ForeignKey(Blueprint, on_delete=models.CASCADE, related_name="revisions")
    revision = models.PositiveIntegerField()
    spec_json = models.JSONField()
    blueprint_kind = models.CharField(
        max_length=20,
        choices=[
            ("solution", "Solution"),
            ("module", "Module"),
            ("bundle", "Bundle"),
        ],
        default="solution",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="blueprint_revisions_created"
    )

    class Meta:
        unique_together = ("blueprint", "revision")
        ordering = ["-revision"]

    def __str__(self) -> str:
        return f"{self.blueprint} v{self.revision}"


class BlueprintDraftSession(models.Model):
    STATUS_CHOICES = [
        ("drafting", "Drafting"),
        ("queued", "Queued"),
        ("ready", "Ready"),
        ("ready_with_errors", "Ready with errors"),
        ("published", "Published"),
        ("archived", "Archived"),
        ("failed", "Failed"),
    ]
    KIND_CHOICES = [
        ("solution", "Solution"),
        ("module", "Module"),
        ("bundle", "Bundle"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    blueprint_kind = models.CharField(max_length=20, choices=KIND_CHOICES, default="solution")
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default="drafting")
    current_draft_json = models.JSONField(null=True, blank=True)
    requirements_summary = models.TextField(blank=True)
    validation_errors_json = models.JSONField(null=True, blank=True)
    suggested_fixes_json = models.JSONField(null=True, blank=True)
    diff_summary = models.TextField(blank=True)
    job_id = models.CharField(max_length=100, blank=True)
    last_error = models.TextField(blank=True)
    context_pack_ids = models.JSONField(default=list, blank=True)
    context_pack_refs_json = models.JSONField(null=True, blank=True)
    effective_context_hash = models.CharField(max_length=64, blank=True)
    effective_context_preview = models.TextField(blank=True)
    linked_blueprint = models.ForeignKey(
        Blueprint, null=True, blank=True, on_delete=models.SET_NULL, related_name="draft_sessions"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="draft_sessions_created"
    )
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="draft_sessions_updated"
    )

    def __str__(self) -> str:
        return self.name


class DraftSessionVoiceNote(models.Model):
    draft_session = models.ForeignKey(BlueprintDraftSession, on_delete=models.CASCADE)
    voice_note = models.ForeignKey(VoiceNote, on_delete=models.CASCADE)
    ordering = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = ("draft_session", "voice_note")
        ordering = ["ordering"]

    def __str__(self) -> str:
        return f"{self.draft_session} -> {self.voice_note}"


class BlueprintInstance(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("planned", "Planned"),
        ("applied", "Applied"),
        ("failed", "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    blueprint = models.ForeignKey(Blueprint, on_delete=models.CASCADE, related_name="instances")
    revision = models.PositiveIntegerField()
    release_id = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    plan_id = models.CharField(max_length=100, blank=True)
    operation_id = models.CharField(max_length=100, blank=True)
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="blueprint_instances_created"
    )

    def __str__(self) -> str:
        return f"{self.blueprint} -> {self.release_id or self.id}"


class Module(models.Model):
    STATUS_CHOICES = [
        ("active", "Active"),
        ("deprecated", "Deprecated"),
        ("archived", "Archived"),
    ]
    TYPE_CHOICES = [
        ("adapter", "Adapter"),
        ("service", "Service"),
        ("ui", "UI"),
        ("workflow", "Workflow"),
        ("schema", "Schema"),
        ("infra", "Infra"),
        ("lib", "Lib"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    namespace = models.CharField(max_length=120)
    name = models.CharField(max_length=120)
    fqn = models.CharField(max_length=240, unique=True)
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    current_version = models.CharField(max_length=64)
    latest_module_spec_json = models.JSONField(null=True, blank=True)
    capabilities_provided_json = models.JSONField(null=True, blank=True)
    interfaces_json = models.JSONField(null=True, blank=True)
    dependencies_json = models.JSONField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="modules_created"
    )
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="modules_updated"
    )

    class Meta:
        unique_together = ("namespace", "name")
        ordering = ["namespace", "name"]

    def __str__(self) -> str:
        return self.fqn


class Bundle(models.Model):
    STATUS_CHOICES = [
        ("active", "Active"),
        ("deprecated", "Deprecated"),
        ("archived", "Archived"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    namespace = models.CharField(max_length=120)
    name = models.CharField(max_length=120)
    fqn = models.CharField(max_length=240, unique=True)
    current_version = models.CharField(max_length=64)
    bundle_spec_json = models.JSONField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="bundles_created"
    )
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="bundles_updated"
    )

    class Meta:
        unique_together = ("namespace", "name")
        ordering = ["namespace", "name"]

    def __str__(self) -> str:
        return self.fqn


class Capability(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    version = models.CharField(max_length=64, default="1.0")
    profiles_json = models.JSONField(null=True, blank=True)
    capability_spec_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} v{self.version}"


class ReleasePlan(models.Model):
    TARGET_CHOICES = [
        ("module", "Module"),
        ("bundle", "Bundle"),
        ("release", "Release"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    target_kind = models.CharField(max_length=20, choices=TARGET_CHOICES)
    target_fqn = models.CharField(max_length=240)
    from_version = models.CharField(max_length=64, blank=True)
    to_version = models.CharField(max_length=64)
    milestones_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="release_plans_created"
    )
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="release_plans_updated"
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.target_kind}:{self.target_fqn} {self.from_version}->{self.to_version}"


class Registry(models.Model):
    TYPE_CHOICES = [
        ("module", "Module"),
        ("bundle", "Bundle"),
        ("blueprint", "Blueprint"),
        ("release", "Release"),
    ]
    STATUS_CHOICES = [
        ("active", "Active"),
        ("inactive", "Inactive"),
        ("error", "Error"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    registry_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    description = models.TextField(blank=True)
    url = models.URLField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")
    last_sync_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="registries_created"
    )
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="registries_updated"
    )

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class Run(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("succeeded", "Succeeded"),
        ("failed", "Failed"),
    ]
    ENTITY_CHOICES = [
        ("blueprint", "Blueprint"),
        ("registry", "Registry"),
        ("module", "Module"),
        ("release_plan", "Release plan"),
        ("dev_task", "Dev task"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    entity_type = models.CharField(max_length=30, choices=ENTITY_CHOICES)
    entity_id = models.UUIDField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    summary = models.CharField(max_length=240, blank=True)
    log_text = models.TextField(blank=True)
    error = models.TextField(blank=True)
    metadata_json = models.JSONField(null=True, blank=True)
    context_pack_refs_json = models.JSONField(null=True, blank=True)
    context_hash = models.CharField(max_length=64, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="runs_created"
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.entity_type}:{self.entity_id} ({self.status})"


class RunArtifact(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    run = models.ForeignKey(Run, on_delete=models.CASCADE, related_name="artifacts")
    name = models.CharField(max_length=200)
    kind = models.CharField(max_length=100, blank=True)
    url = models.TextField(blank=True)
    metadata_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self) -> str:
        return f"{self.name} ({self.run_id})"


class ContextPack(models.Model):
    PURPOSE_CHOICES = [
        ("any", "Any"),
        ("planner", "Planner"),
        ("coder", "Coder"),
        ("deployer", "Deployer"),
        ("operator", "Operator"),
    ]
    SCOPE_CHOICES = [
        ("global", "Global"),
        ("namespace", "Namespace"),
        ("project", "Project"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES, default="any")
    scope = models.CharField(max_length=20, choices=SCOPE_CHOICES)
    namespace = models.CharField(max_length=120, blank=True)
    project_key = models.CharField(max_length=120, blank=True)
    version = models.CharField(max_length=64)
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)
    content_markdown = models.TextField()
    applies_to_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="context_packs_created"
    )
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="context_packs_updated"
    )

    class Meta:
        ordering = ["name"]
        unique_together = ("name", "version", "purpose", "scope", "namespace", "project_key")

    def __str__(self) -> str:
        return f"{self.name} ({self.scope}) v{self.version}"


class DevTask(models.Model):
    STATUS_CHOICES = [
        ("queued", "Queued"),
        ("running", "Running"),
        ("succeeded", "Succeeded"),
        ("failed", "Failed"),
        ("canceled", "Canceled"),
    ]
    TYPE_CHOICES = [
        ("codegen", "Codegen"),
        ("module_scaffold", "Module scaffold"),
        ("release_plan_generate", "Release plan generate"),
        ("registry_sync", "Registry sync"),
        ("deploy", "Deploy"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=240)
    task_type = models.CharField(max_length=40, choices=TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="queued")
    priority = models.IntegerField(default=0)
    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=3)
    locked_by = models.CharField(max_length=120, blank=True)
    locked_at = models.DateTimeField(null=True, blank=True)
    source_entity_type = models.CharField(max_length=60)
    source_entity_id = models.UUIDField()
    source_run = models.ForeignKey(
        Run, null=True, blank=True, on_delete=models.SET_NULL, related_name="dev_tasks_source"
    )
    input_artifact_key = models.CharField(max_length=200, blank=True)
    result_run = models.ForeignKey(
        Run, null=True, blank=True, on_delete=models.SET_NULL, related_name="dev_tasks_result"
    )
    last_error = models.TextField(blank=True)
    context_purpose = models.CharField(max_length=20, default="any")
    context_packs = models.ManyToManyField(ContextPack, blank=True, related_name="dev_tasks")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="dev_tasks_created"
    )
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="dev_tasks_updated"
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.title} ({self.task_type})"


class ProvisionedInstance(models.Model):
    STATUS_CHOICES = [
        ("requested", "Requested"),
        ("provisioning", "Provisioning"),
        ("running", "Running"),
        ("ready", "Ready"),
        ("error", "Error"),
        ("terminating", "Terminating"),
        ("terminated", "Terminated"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    aws_region = models.CharField(max_length=50)
    instance_id = models.CharField(max_length=64, blank=True)
    instance_type = models.CharField(max_length=64)
    ami_id = models.CharField(max_length=64)
    security_group_id = models.CharField(max_length=64, blank=True)
    subnet_id = models.CharField(max_length=64, blank=True)
    vpc_id = models.CharField(max_length=64, blank=True)
    public_ip = models.GenericIPAddressField(null=True, blank=True)
    private_ip = models.GenericIPAddressField(null=True, blank=True)
    ssm_status = models.CharField(max_length=64, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="requested")
    last_error = models.TextField(blank=True)
    tags_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="provisioned_instances_created"
    )
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="provisioned_instances_updated"
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.name} ({self.aws_region})"
