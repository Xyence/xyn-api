from django.db import models
from django.db.models import Max
from django.contrib.postgres.search import SearchVectorField
from django.utils import timezone
from django.utils.text import slugify
from ckeditor_uploader.fields import RichTextUploadingField


class Article(models.Model):
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("published", "Published"),
    ]

    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=220, unique=True, blank=True)
    summary = models.TextField(blank=True)
    body = RichTextUploadingField()
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


class ArticleVersion(models.Model):
    SOURCE_CHOICES = [
        ("ai", "AI"),
        ("manual", "Manual"),
    ]

    article = models.ForeignKey(Article, related_name="versions", on_delete=models.CASCADE)
    version_number = models.PositiveIntegerField()
    title = models.CharField(max_length=200)
    summary = models.TextField(blank=True)
    body = RichTextUploadingField()
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


class GitHubConfig(models.Model):
    name = models.CharField(max_length=100, default="default")
    access_token = models.TextField()
    social_account = models.ForeignKey(
        "socialaccount.SocialAccount",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    organization = models.CharField(max_length=200)
    organization_ref = models.ForeignKey(
        "GitHubOrganization",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"GitHub Config ({self.organization})"

    def organization_login(self) -> str:
        if self.organization_ref:
            return self.organization_ref.login
        return self.organization


class GitHubOrganization(models.Model):
    config = models.ForeignKey(GitHubConfig, on_delete=models.CASCADE, related_name="orgs")
    login = models.CharField(max_length=200)
    name = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("config", "login")

    def __str__(self) -> str:
        return self.name or self.login


class GitHubRepo(models.Model):
    config = models.ForeignKey(GitHubConfig, on_delete=models.CASCADE, related_name="repos")
    name = models.CharField(max_length=200)
    full_name = models.CharField(max_length=300, unique=True)
    default_branch = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    last_indexed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return self.full_name


class GitHubRepoChunk(models.Model):
    repo = models.ForeignKey(GitHubRepo, on_delete=models.CASCADE, related_name="chunks")
    path = models.CharField(max_length=500)
    content = models.TextField()
    content_search = SearchVectorField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["path"]),
        ]

    def __str__(self) -> str:
        return f"{self.repo.full_name}:{self.path}"
