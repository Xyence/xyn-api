from django.db import migrations


def forward(apps, schema_editor):
    Workspace = apps.get_model("xyn_orchestrator", "Workspace")
    ArtifactType = apps.get_model("xyn_orchestrator", "ArtifactType")
    Artifact = apps.get_model("xyn_orchestrator", "Artifact")
    ArtifactRevision = apps.get_model("xyn_orchestrator", "ArtifactRevision")
    ArtifactEvent = apps.get_model("xyn_orchestrator", "ArtifactEvent")
    ArtifactExternalRef = apps.get_model("xyn_orchestrator", "ArtifactExternalRef")
    WorkspaceMembership = apps.get_model("xyn_orchestrator", "WorkspaceMembership")
    RoleBinding = apps.get_model("xyn_orchestrator", "RoleBinding")
    Article = apps.get_model("xyn_orchestrator", "Article")

    platform_builder, _ = Workspace.objects.get_or_create(
        slug="platform-builder",
        defaults={"name": "Platform Builder", "description": "Application and platform engineering workspace."},
    )
    civic_lab, _ = Workspace.objects.get_or_create(
        slug="civic-lab",
        defaults={"name": "Civic Lab", "description": "Knowledge publishing and deliberation workspace."},
    )

    article_type, _ = ArtifactType.objects.get_or_create(
        slug="article",
        defaults={
            "name": "Article",
            "description": "Governed published knowledge artifact.",
            "icon": "BookText",
            "schema_json": {
                "required": ["title"],
                "properties": {
                    "title": {"type": "string"},
                    "summary": {"type": "string"},
                    "body_markdown": {"type": "string"},
                    "body_html": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
    )

    for rb in RoleBinding.objects.filter(role="platform_admin").select_related("user_identity"):
        for ws in (platform_builder, civic_lab):
            WorkspaceMembership.objects.get_or_create(
                workspace=ws,
                user_identity=rb.user_identity,
                defaults={"role": "admin", "termination_authority": True},
            )

    for article in Article.objects.all().order_by("created_at"):
        ext = ArtifactExternalRef.objects.filter(system="django", external_id=str(article.id)).first()
        if ext:
            artifact = ext.artifact
        else:
            artifact = Artifact.objects.create(
                workspace=civic_lab,
                type=article_type,
                title=article.title,
                status="published" if article.status == "published" else "draft",
                version=1,
                visibility="public" if article.status == "published" else "private",
                published_at=article.published_at,
                provenance_json={
                    "source_system": "django",
                    "source_id": str(article.id),
                    "original_slug": article.slug,
                    "original_url_path": f"/articles/{article.slug}",
                },
                scope_json={"slug": article.slug},
            )
            ArtifactExternalRef.objects.create(
                artifact=artifact,
                system="django",
                external_id=str(article.id),
                slug_path=article.slug,
            )

        if not ArtifactRevision.objects.filter(artifact=artifact).exists():
            ArtifactRevision.objects.create(
                artifact=artifact,
                revision_number=1,
                content_json={
                    "title": article.title,
                    "summary": article.summary,
                    "body_html": article.body,
                    "body_markdown": "",
                    "tags": [],
                },
            )

        if not ArtifactEvent.objects.filter(artifact=artifact, event_type="imported_from_django").exists():
            ArtifactEvent.objects.create(
                artifact=artifact,
                event_type="imported_from_django",
                payload_json={"source_id": str(article.id), "status": article.status},
            )


def backward(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0062_workspace_artifact_registry"),
    ]

    operations = [
        migrations.RunPython(forward, backward),
    ]
