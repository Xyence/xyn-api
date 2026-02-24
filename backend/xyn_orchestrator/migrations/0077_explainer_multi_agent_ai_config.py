from django.db import migrations, models
from django.db.models import Q


EXPLAINER_PURPOSES = [
    ("explainer_script", "Explainer Script", "Generate explainer narration scripts."),
    ("explainer_storyboard", "Explainer Storyboard", "Generate storyboard scene structures."),
    ("explainer_visual_prompts", "Explainer Visual Prompts", "Generate visual prompt sets per scene."),
    ("explainer_narration", "Explainer Narration", "Refine narration for spoken delivery."),
    ("explainer_title_description", "Explainer Title & Description", "Generate title/description/CTA variants."),
]

DEFAULT_PACK_CONTENT = {
    "explainer_script": """# Explainer Script Defaults
- Audience: mixed technical/non-technical
- Tone: clear, confident, warm, governance-substrate feel
- Structure: problem -> approach -> why it matters -> concrete example
- Avoid: unverified claims, competitor callouts, political content
- Output: spoken narration text, optionally HOOK/BODY/CLOSE markers
""",
    "explainer_storyboard": """# Explainer Storyboard Defaults
- Output MUST be strict JSON matching canonical video_spec_json shape
- Typical scene duration: 8-20 seconds
- Include timing, on-screen text, visuals, narration per scene
- Do not invent facts; structure only from provided inputs
""",
    "explainer_visual_prompts": """# Explainer Visual Prompt Defaults
- Visual language: clean diagrams, UI callouts, minimal iconography, brand-safe
- Default: avoid photoreal humans
- For each scene include: image_prompt, optional negative_prompt, motion_hint, aspect_ratio=16:9
- Output: JSON keyed by scene_id
""",
    "explainer_narration": """# Explainer Narration Defaults
- Spoken-friendly rewrite with smooth cadence
- Avoid jargon unless explicitly requested
- Optional SSML only when requested
- Optional caption chunking guidance
""",
    "explainer_title_description": """# Explainer Title/Description Defaults
- Produce 5 title options, 2 descriptions, and 3 CTAs
- No hype; concise and concrete
- Output JSON: {titles, descriptions, ctas}
""",
}


def _seed_explainer_purposes_and_packs(apps, schema_editor):
    AgentPurpose = apps.get_model("xyn_orchestrator", "AgentPurpose")
    AgentDefinition = apps.get_model("xyn_orchestrator", "AgentDefinition")
    AgentDefinitionPurpose = apps.get_model("xyn_orchestrator", "AgentDefinitionPurpose")
    ContextPack = apps.get_model("xyn_orchestrator", "ContextPack")

    purpose_rows = {}
    for slug, name, description in EXPLAINER_PURPOSES:
        row, _ = AgentPurpose.objects.get_or_create(
            slug=slug,
            defaults={
                "name": name,
                "description": description,
                "status": "active",
                "enabled": True,
                "preamble": f"Purpose: {slug}. {description}",
            },
        )
        updates = []
        if row.status != "active":
            row.status = "active"
            updates.append("status")
        if not row.enabled:
            row.enabled = True
            updates.append("enabled")
        if not row.name:
            row.name = name
            updates.append("name")
        if not row.description:
            row.description = description
            updates.append("description")
        if updates:
            row.save(update_fields=updates + ["updated_at"])
        purpose_rows[slug] = row

    pack_rows = {}
    for slug, _, _ in EXPLAINER_PURPOSES:
        pack_name = f"{slug.replace('_', '-').strip()}-default"
        pack, _ = ContextPack.objects.get_or_create(
            name=pack_name,
            version="1.0.0",
            purpose=slug,
            scope="global",
            namespace="",
            project_key="",
            defaults={
                "is_active": True,
                "is_default": False,
                "content_markdown": DEFAULT_PACK_CONTENT.get(slug, ""),
                "applies_to_json": {"purpose": slug, "artifact_type": "video_explainer"},
            },
        )
        updates = []
        if not pack.is_active:
            pack.is_active = True
            updates.append("is_active")
        if not pack.content_markdown:
            pack.content_markdown = DEFAULT_PACK_CONTENT.get(slug, "")
            updates.append("content_markdown")
        if updates:
            pack.save(update_fields=updates + ["updated_at"])
        pack_rows[slug] = pack

    for slug, purpose in purpose_rows.items():
        pack = pack_rows.get(slug)
        if not pack:
            continue
        purpose.default_context_pack_refs_json = [
            {
                "id": str(pack.id),
                "name": pack.name,
                "purpose": pack.purpose,
                "scope": pack.scope,
                "version": pack.version,
            }
        ]
        purpose.save(update_fields=["default_context_pack_refs_json", "updated_at"])

    for slug, purpose in purpose_rows.items():
        AgentDefinitionPurpose.objects.filter(purpose_id=purpose.id, is_default_for_purpose=True).update(is_default_for_purpose=False)
        linked = list(
            AgentDefinitionPurpose.objects.select_related("agent_definition")
            .filter(purpose_id=purpose.id, agent_definition__enabled=True, agent_definition__is_default=True)
            .order_by("agent_definition__slug")
        )
        if len(linked) == 1:
            row = linked[0]
            row.is_default_for_purpose = True
            row.save(update_fields=["is_default_for_purpose"])

    default_agent = AgentDefinition.objects.filter(slug="default-assistant", enabled=True).first()
    if default_agent:
        for purpose in purpose_rows.values():
            link, _ = AgentDefinitionPurpose.objects.get_or_create(agent_definition_id=default_agent.id, purpose_id=purpose.id)
            if not AgentDefinitionPurpose.objects.filter(purpose_id=purpose.id, is_default_for_purpose=True).exists():
                link.is_default_for_purpose = True
                link.save(update_fields=["is_default_for_purpose"])


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0076_videorender_input_snapshot_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="agentdefinitionpurpose",
            name="is_default_for_purpose",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="agentpurpose",
            name="default_context_pack_refs_json",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="artifact",
            name="video_ai_config_json",
            field=models.JSONField(blank=True, null=True),
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
                    ("explainer_script", "Explainer Script"),
                    ("explainer_storyboard", "Explainer Storyboard"),
                    ("explainer_visual_prompts", "Explainer Visual Prompts"),
                    ("explainer_narration", "Explainer Narration"),
                    ("explainer_title_description", "Explainer Title Description"),
                ],
                default="any",
                max_length=40,
            ),
        ),
        migrations.AddConstraint(
            model_name="agentdefinitionpurpose",
            constraint=models.UniqueConstraint(
                fields=("purpose",),
                condition=Q(is_default_for_purpose=True),
                name="uniq_default_agent_per_purpose",
            ),
        ),
        migrations.RunPython(_seed_explainer_purposes_and_packs, migrations.RunPython.noop),
    ]
