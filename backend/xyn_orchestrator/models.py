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
    spec_text = models.TextField(blank=True)
    metadata_json = models.JSONField(null=True, blank=True)
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
    blueprint = models.ForeignKey(
        Blueprint, null=True, blank=True, on_delete=models.SET_NULL, related_name="draft_sessions_source"
    )
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


class ReleaseTarget(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    blueprint = models.ForeignKey(Blueprint, on_delete=models.CASCADE, related_name="release_targets")
    name = models.CharField(max_length=200)
    environment = models.CharField(max_length=120, blank=True)
    target_instance_ref = models.CharField(max_length=120, blank=True)
    target_instance = models.ForeignKey(
        "ProvisionedInstance", null=True, blank=True, on_delete=models.SET_NULL, related_name="release_targets"
    )
    fqdn = models.CharField(max_length=200)
    dns_json = models.JSONField(null=True, blank=True)
    runtime_json = models.JSONField(null=True, blank=True)
    tls_json = models.JSONField(null=True, blank=True)
    env_json = models.JSONField(null=True, blank=True)
    secret_refs_json = models.JSONField(null=True, blank=True)
    config_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="release_targets_created"
    )
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="release_targets_updated"
    )

    class Meta:
        ordering = ["-created_at"]
        unique_together = ("blueprint", "name")

    def __str__(self) -> str:
        return f"{self.blueprint} target {self.name}"


class IdentityProvider(models.Model):
    id = models.CharField(primary_key=True, max_length=120)
    display_name = models.CharField(max_length=200)
    enabled = models.BooleanField(default=True)
    issuer = models.URLField()
    discovery_json = models.JSONField(null=True, blank=True)
    client_id = models.CharField(max_length=240)
    client_secret_ref_json = models.JSONField(null=True, blank=True)
    scopes_json = models.JSONField(null=True, blank=True)
    pkce_enabled = models.BooleanField(default=True)
    prompt = models.CharField(max_length=40, blank=True)
    domain_rules_json = models.JSONField(null=True, blank=True)
    claims_json = models.JSONField(null=True, blank=True)
    audience_rules_json = models.JSONField(null=True, blank=True)
    cached_discovery_doc = models.JSONField(null=True, blank=True)
    cached_jwks = models.JSONField(null=True, blank=True)
    last_discovery_refresh_at = models.DateTimeField(null=True, blank=True)
    jwks_cached_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="identity_providers_created"
    )

    class Meta:
        ordering = ["id"]

    def __str__(self) -> str:
        return self.display_name or self.id


class AppOIDCClient(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    app_id = models.CharField(max_length=120)
    login_mode = models.CharField(max_length=40, default="redirect")
    default_provider = models.ForeignKey(
        IdentityProvider, null=True, blank=True, on_delete=models.SET_NULL, related_name="default_for_apps"
    )
    allowed_providers_json = models.JSONField(null=True, blank=True)
    redirect_uris_json = models.JSONField(null=True, blank=True)
    post_logout_redirect_uris_json = models.JSONField(null=True, blank=True)
    session_json = models.JSONField(null=True, blank=True)
    token_validation_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="oidc_clients_created"
    )

    class Meta:
        ordering = ["app_id", "-created_at"]

    def __str__(self) -> str:
        return self.app_id


class UserIdentity(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    provider_id = models.CharField(max_length=120, blank=True)
    provider = models.CharField(max_length=50)
    issuer = models.CharField(max_length=240)
    subject = models.CharField(max_length=240)
    email = models.CharField(max_length=240, blank=True)
    display_name = models.CharField(max_length=240, blank=True)
    claims_json = models.JSONField(null=True, blank=True)
    last_login_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("issuer", "subject")
        ordering = ["-updated_at"]

    def __str__(self) -> str:
        return f"{self.provider}:{self.subject}"


class RoleBinding(models.Model):
    SCOPE_CHOICES = [
        ("platform", "Platform"),
        ("tenant", "Tenant"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_identity = models.ForeignKey(
        UserIdentity, on_delete=models.CASCADE, related_name="role_bindings"
    )
    scope_kind = models.CharField(max_length=20, choices=SCOPE_CHOICES, default="platform")
    scope_id = models.UUIDField(null=True, blank=True)
    role = models.CharField(max_length=120)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user_identity", "scope_kind", "scope_id", "role")
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.user_identity_id} {self.role}"


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


class Environment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=120, unique=True)
    base_domain = models.CharField(max_length=200, blank=True)
    aws_region = models.CharField(max_length=50, blank=True)
    metadata_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class Tenant(models.Model):
    STATUS_CHOICES = [
        ("active", "Active"),
        ("suspended", "Suspended"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=120, unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")
    metadata_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class Contact(models.Model):
    STATUS_CHOICES = [
        ("active", "Active"),
        ("inactive", "Inactive"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="contacts")
    name = models.CharField(max_length=200)
    email = models.EmailField(null=True, blank=True)
    phone = models.CharField(max_length=50, null=True, blank=True)
    role_title = models.CharField(max_length=120, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")
    metadata_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} ({self.tenant.name})"


class TenantMembership(models.Model):
    ROLE_CHOICES = [
        ("tenant_admin", "Tenant Admin"),
        ("tenant_operator", "Tenant Operator"),
        ("tenant_viewer", "Tenant Viewer"),
    ]
    STATUS_CHOICES = [
        ("active", "Active"),
        ("inactive", "Inactive"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="memberships")
    user_identity = models.ForeignKey(UserIdentity, on_delete=models.CASCADE, related_name="memberships")
    role = models.CharField(max_length=40, choices=ROLE_CHOICES, default="tenant_viewer")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["tenant__name"]
        unique_together = ("tenant", "user_identity")

    def __str__(self) -> str:
        return f"{self.tenant.name} - {self.user_identity.email or self.user_identity.subject}"


class BrandProfile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.OneToOneField(Tenant, on_delete=models.CASCADE, related_name="brand_profile")
    display_name = models.CharField(max_length=200, null=True, blank=True)
    logo_url = models.CharField(max_length=500, null=True, blank=True)
    primary_color = models.CharField(max_length=40, null=True, blank=True)
    secondary_color = models.CharField(max_length=40, null=True, blank=True)
    theme_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["tenant__name"]

    def __str__(self) -> str:
        return f"{self.tenant.name} branding"


class PlatformBranding(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    brand_name = models.CharField(max_length=200, default="Xyn")
    logo_url = models.CharField(max_length=500, null=True, blank=True)
    favicon_url = models.CharField(max_length=500, null=True, blank=True)
    primary_color = models.CharField(max_length=40, default="#0f4c81")
    background_color = models.CharField(max_length=40, default="#f5f7fb")
    background_gradient = models.CharField(max_length=240, null=True, blank=True)
    text_color = models.CharField(max_length=40, default="#10203a")
    font_family = models.CharField(max_length=120, null=True, blank=True)
    button_radius_px = models.IntegerField(default=12)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="platform_branding_updates"
    )

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self) -> str:
        return self.brand_name


class AppBrandingOverride(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    app_id = models.CharField(max_length=120, unique=True)
    display_name = models.CharField(max_length=200, null=True, blank=True)
    logo_url = models.CharField(max_length=500, null=True, blank=True)
    primary_color = models.CharField(max_length=40, null=True, blank=True)
    background_color = models.CharField(max_length=40, null=True, blank=True)
    background_gradient = models.CharField(max_length=240, null=True, blank=True)
    text_color = models.CharField(max_length=40, null=True, blank=True)
    font_family = models.CharField(max_length=120, null=True, blank=True)
    button_radius_px = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="app_branding_updates"
    )

    class Meta:
        ordering = ["app_id"]

    def __str__(self) -> str:
        return self.app_id


class Device(models.Model):
    STATUS_CHOICES = [
        ("active", "Active"),
        ("offline", "Offline"),
        ("unknown", "Unknown"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="devices")
    name = models.CharField(max_length=200)
    device_type = models.CharField(max_length=120)
    mgmt_ip = models.CharField(max_length=120, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="unknown")
    tags = models.JSONField(null=True, blank=True)
    metadata_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        unique_together = ("tenant", "name")
        indexes = [models.Index(fields=["tenant", "status"])]

    def __str__(self) -> str:
        return f"{self.name} ({self.tenant.name})"


class ReleasePlan(models.Model):
    TARGET_CHOICES = [
        ("module", "Module"),
        ("bundle", "Bundle"),
        ("release", "Release"),
        ("blueprint", "Blueprint"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    target_kind = models.CharField(max_length=20, choices=TARGET_CHOICES)
    target_fqn = models.CharField(max_length=240)
    from_version = models.CharField(max_length=64, blank=True)
    to_version = models.CharField(max_length=64)
    milestones_json = models.JSONField(null=True, blank=True)
    blueprint = models.ForeignKey(
        "Blueprint", null=True, blank=True, on_delete=models.SET_NULL, related_name="release_plans"
    )
    environment = models.ForeignKey(
        "Environment", null=True, blank=True, on_delete=models.SET_NULL, related_name="release_plans"
    )
    last_run = models.ForeignKey(
        "Run", null=True, blank=True, on_delete=models.SET_NULL, related_name="release_plans"
    )
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


class Release(models.Model):
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("published", "Published"),
        ("deprecated", "Deprecated"),
    ]
    BUILD_STATE_CHOICES = [
        ("draft", "Draft"),
        ("building", "Building"),
        ("ready", "Ready"),
        ("failed", "Failed"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    blueprint = models.ForeignKey(
        "Blueprint", null=True, blank=True, on_delete=models.SET_NULL, related_name="releases"
    )
    version = models.CharField(max_length=64)
    release_plan = models.ForeignKey(
        ReleasePlan, null=True, blank=True, on_delete=models.SET_NULL, related_name="releases"
    )
    created_from_run = models.ForeignKey(
        "Run", null=True, blank=True, on_delete=models.SET_NULL, related_name="releases"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")
    build_state = models.CharField(max_length=20, choices=BUILD_STATE_CHOICES, default="draft")
    artifacts_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="releases_created"
    )
    updated_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="releases_updated"
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.version} ({self.status})"


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


class RunCommandExecution(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("succeeded", "Succeeded"),
        ("failed", "Failed"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    run = models.ForeignKey(Run, on_delete=models.CASCADE, related_name="command_executions")
    step_name = models.CharField(max_length=120, blank=True)
    command_index = models.PositiveIntegerField(default=0)
    shell = models.CharField(max_length=40, default="sh")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    exit_code = models.IntegerField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    ssm_command_id = models.CharField(max_length=120, blank=True)
    stdout = models.TextField(blank=True)
    stderr = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["created_at"]


class ReleasePlanDeployState(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    release_plan = models.ForeignKey(ReleasePlan, on_delete=models.CASCADE, related_name="deploy_states")
    instance = models.ForeignKey(
        "ProvisionedInstance", on_delete=models.CASCADE, related_name="deploy_states"
    )
    last_applied_hash = models.CharField(max_length=64, blank=True)
    last_applied_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("release_plan", "instance")


class ReleasePlanDeployment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    release_plan = models.ForeignKey(ReleasePlan, on_delete=models.CASCADE, related_name="deployments")
    instance = models.ForeignKey(
        "ProvisionedInstance", on_delete=models.CASCADE, related_name="deployments"
    )
    last_applied_hash = models.CharField(max_length=64, blank=True)
    last_applied_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("release_plan", "instance")


class Deployment(models.Model):
    STATUS_CHOICES = [
        ("queued", "Queued"),
        ("running", "Running"),
        ("succeeded", "Succeeded"),
        ("failed", "Failed"),
    ]
    KIND_CHOICES = [
        ("release", "Release"),
        ("release_plan", "Release plan"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    idempotency_key = models.CharField(max_length=64, unique=True)
    idempotency_base = models.CharField(max_length=64, db_index=True)
    app_id = models.CharField(max_length=120, blank=True)
    environment = models.ForeignKey(
        "Environment", null=True, blank=True, on_delete=models.SET_NULL, related_name="deployments"
    )
    release = models.ForeignKey("Release", on_delete=models.CASCADE, related_name="deployments")
    instance = models.ForeignKey(
        "ProvisionedInstance", on_delete=models.CASCADE, related_name="deployment_records"
    )
    release_plan = models.ForeignKey(
        ReleasePlan, null=True, blank=True, on_delete=models.SET_NULL, related_name="deployment_records"
    )
    deploy_kind = models.CharField(max_length=20, choices=KIND_CHOICES, default="release")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="queued")
    submitted_by = models.CharField(max_length=120, blank=True)
    transport = models.CharField(max_length=40, default="ssm")
    transport_ref = models.JSONField(null=True, blank=True)
    health_check_status = models.CharField(max_length=20, blank=True)
    health_check_details_json = models.JSONField(null=True, blank=True)
    stdout_excerpt = models.TextField(blank=True)
    stderr_excerpt = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    artifacts_json = models.JSONField(null=True, blank=True)
    run = models.ForeignKey(Run, null=True, blank=True, on_delete=models.SET_NULL, related_name="deployments")
    rollback_of = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="rollback_attempts"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

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


class EnvironmentAppState(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    environment = models.ForeignKey(
        "Environment", on_delete=models.CASCADE, related_name="app_states"
    )
    app_id = models.CharField(max_length=120)
    current_release = models.ForeignKey(
        "Release", null=True, blank=True, on_delete=models.SET_NULL, related_name="current_in_env_states"
    )
    last_good_release = models.ForeignKey(
        "Release", null=True, blank=True, on_delete=models.SET_NULL, related_name="last_good_in_env_states"
    )
    last_deployed_at = models.DateTimeField(null=True, blank=True)
    last_good_at = models.DateTimeField(null=True, blank=True)
    last_deploy_run = models.ForeignKey(
        "Run", null=True, blank=True, on_delete=models.SET_NULL, related_name="environment_app_states"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("environment", "app_id")
        ordering = ["environment__name", "app_id"]

    def __str__(self) -> str:
        return f"{self.environment.slug}:{self.app_id}"


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
        ("deploy_release_plan", "Deploy release plan"),
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
    work_item_id = models.CharField(max_length=120, blank=True)
    result_run = models.ForeignKey(
        Run, null=True, blank=True, on_delete=models.SET_NULL, related_name="dev_tasks_result"
    )
    last_error = models.TextField(blank=True)
    context_purpose = models.CharField(max_length=20, default="any")
    context_packs = models.ManyToManyField(ContextPack, blank=True, related_name="dev_tasks")
    target_instance = models.ForeignKey(
        "ProvisionedInstance", null=True, blank=True, on_delete=models.SET_NULL, related_name="dev_tasks"
    )
    force = models.BooleanField(default=False)
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
    HEALTH_CHOICES = [
        ("unknown", "Unknown"),
        ("healthy", "Healthy"),
        ("degraded", "Degraded"),
        ("failed", "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    environment = models.ForeignKey(
        "Environment", null=True, blank=True, on_delete=models.SET_NULL, related_name="instances"
    )
    aws_region = models.CharField(max_length=50)
    instance_id = models.CharField(max_length=255, blank=True)
    runtime_substrate = models.CharField(max_length=20, default="local")
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
    desired_release = models.ForeignKey(
        "Release", null=True, blank=True, on_delete=models.SET_NULL, related_name="desired_instances"
    )
    observed_release = models.ForeignKey(
        "Release", null=True, blank=True, on_delete=models.SET_NULL, related_name="observed_instances"
    )
    observed_at = models.DateTimeField(null=True, blank=True)
    last_deploy_run = models.ForeignKey(
        "Run", null=True, blank=True, on_delete=models.SET_NULL, related_name="deploy_runs"
    )
    health_status = models.CharField(max_length=20, choices=HEALTH_CHOICES, default="unknown")
    tags_json = models.JSONField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
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


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    message = models.TextField()
    metadata_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="audit_logs"
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.message[:120]
