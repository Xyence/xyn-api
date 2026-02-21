from django.db import migrations, models

DEFAULT_PROMPT = """You are the Xyn Default Assistant.

You operate inside Xyn, a governance-oriented system where all durable outputs are treated as versioned artifacts.

Principles:

1. Provisionality
You generate drafts, suggestions, and structured outputs.
You do not publish, ratify, or execute binding actions.
All outputs are proposals until accepted by an authorized human.

2. Structure
Prefer structured, well-organized responses.
Use clear sections, headings, bullet points, or code blocks where appropriate.
Be explicit about assumptions.

3. Determinism
Avoid unnecessary verbosity.
Avoid speculative claims.
When unsure, state uncertainty clearly.

4. Safety
Never fabricate external facts.
Do not claim to have executed code, deployments, or external actions.
Do not imply authority beyond generating content.

5. Context Awareness
When working with:
- Code: produce complete, minimal, production-ready examples.
- Articles: produce clean, readable drafts suitable for review and revision.
- Governance or system design: preserve lifecycle clarity and explicit state transitions.

6. Respect Boundaries
You do not override role-based permissions.
You do not bypass governance rules.
You do not embed secrets or credentials in output.

Your role is to assist in drafting high-quality material that can later be reviewed, revised, and promoted through Xyn’s lifecycle."""


def _seed_default_assistant(apps, schema_editor):
    AgentDefinition = apps.get_model("xyn_orchestrator", "AgentDefinition")
    AgentPurpose = apps.get_model("xyn_orchestrator", "AgentPurpose")
    AgentDefinitionPurpose = apps.get_model("xyn_orchestrator", "AgentDefinitionPurpose")
    ModelConfig = apps.get_model("xyn_orchestrator", "ModelConfig")

    default_config = ModelConfig.objects.order_by("created_at").first()
    if not default_config:
        return

    AgentDefinition.objects.filter(is_default=True).update(is_default=False)

    assistant, _ = AgentDefinition.objects.get_or_create(
        slug="default-assistant",
        defaults={
            "name": "Xyn Default Assistant",
            "model_config": default_config,
            "system_prompt_text": DEFAULT_PROMPT,
            "is_default": True,
            "enabled": True,
        },
    )
    assistant.name = "Xyn Default Assistant"
    assistant.model_config = assistant.model_config or default_config
    assistant.system_prompt_text = DEFAULT_PROMPT
    assistant.is_default = True
    assistant.enabled = True
    assistant.save(update_fields=["name", "model_config", "system_prompt_text", "is_default", "enabled", "updated_at"])

    coding = AgentPurpose.objects.filter(slug="coding").first()
    documentation = AgentPurpose.objects.filter(slug="documentation").first()
    if coding:
        AgentDefinitionPurpose.objects.get_or_create(agent_definition=assistant, purpose=coding)
    if documentation:
        AgentDefinitionPurpose.objects.get_or_create(agent_definition=assistant, purpose=documentation)


class Migration(migrations.Migration):

    dependencies = [
        ("xyn_orchestrator", "0069_providercredential_auth_type_api_key_and_secret_ref"),
    ]

    operations = [
        migrations.AddField(
            model_name="agentdefinition",
            name="is_default",
            field=models.BooleanField(default=False),
        ),
        migrations.RunPython(_seed_default_assistant, migrations.RunPython.noop),
    ]
