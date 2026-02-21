import base64
import hashlib
import logging
import os
from typing import Any, Dict, List, Optional

import requests
from cryptography.fernet import Fernet

from .models import (
    AgentDefinition,
    AgentPurpose,
    ModelProvider,
    OpenAIConfig,
    ProviderCredential,
    SecretRef,
    SecretStore,
)
from .oidc import resolve_secret_ref
from .secret_stores import normalize_secret_logical_name, write_secret_value

logger = logging.getLogger(__name__)

DEFAULT_ASSISTANT_PROMPT = """You are the Xyn Default Assistant.

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

PROVIDER_ENV_API_KEY = {
    "openai": ["XYN_OPENAI_API_KEY", "OPENAI_API_KEY"],
    "anthropic": ["XYN_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"],
    "google": ["XYN_GOOGLE_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"],
}


class AiConfigError(RuntimeError):
    pass


class AiInvokeError(RuntimeError):
    pass


def assemble_system_prompt(agent_prompt: Optional[str], purpose_preamble: Optional[str]) -> str:
    preamble = str(purpose_preamble or "").strip()
    prompt = str(agent_prompt or "").strip()
    if preamble and prompt:
        return f"{preamble}\n\n{prompt}"
    return preamble or prompt


def _fernet() -> Fernet:
    raw = str(os.environ.get("XYN_CREDENTIALS_ENCRYPTION_KEY") or os.environ.get("XYN_SECRET_KEY") or "").strip()
    if not raw:
        raise AiConfigError("Missing XYN_CREDENTIALS_ENCRYPTION_KEY")
    try:
        return Fernet(raw.encode("utf-8"))
    except Exception:
        digest = hashlib.sha256(raw.encode("utf-8")).digest()
        key = base64.urlsafe_b64encode(digest)
        return Fernet(key)


def encrypt_api_key(api_key: str) -> str:
    value = str(api_key or "").strip()
    if not value:
        raise AiConfigError("api_key is required")
    return _fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_api_key(ciphertext: str) -> str:
    value = str(ciphertext or "").strip()
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except Exception as exc:
        raise AiConfigError("Credential decryption failed") from exc


def mask_secret(secret: str) -> Dict[str, Any]:
    value = str(secret or "")
    if not value:
        return {"has_value": False, "masked": None, "last4": None}
    last4 = value[-4:] if len(value) >= 4 else value
    return {"has_value": True, "masked": "***" + last4, "last4": last4}


def _read_provider_env_key(provider_slug: str) -> str:
    for key in PROVIDER_ENV_API_KEY.get(provider_slug, []):
        value = str(os.environ.get(key) or "").strip()
        if value:
            return value
    return ""


def _credential_api_key(credential: Optional[ProviderCredential], provider_slug: str) -> str:
    if credential is None:
        return ""
    if not credential.enabled:
        return ""
    if credential.auth_type == "api_key":
        if credential.secret_ref_id:
            ref = SecretRef.objects.select_related("store").filter(id=credential.secret_ref_id).first()
            if ref and ref.external_ref:
                resolved = resolve_secret_ref({"type": "aws.secrets_manager", "ref": ref.external_ref})
                return str(resolved or "").strip()
        return decrypt_api_key(str(credential.api_key_encrypted or ""))
    env_var = str(credential.env_var_name or "").strip()
    if not env_var:
        return ""
    return str(os.environ.get(env_var) or "").strip()


def _resolve_model_api_key(provider_slug: str, credential: Optional[ProviderCredential]) -> str:
    api_key = _credential_api_key(credential, provider_slug)
    if api_key:
        return api_key
    return _read_provider_env_key(provider_slug)


def _serialize_messages_for_provider(messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
    cooked: List[Dict[str, str]] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "user").strip().lower()
        content = str(message.get("content") or "")
        if role not in {"system", "user", "assistant"}:
            role = "user"
        cooked.append({"role": role, "content": content})
    return cooked


def resolve_ai_config(*, purpose_slug: Optional[str] = None, agent_slug: Optional[str] = None) -> Dict[str, Any]:
    purpose = str(purpose_slug or "").strip().lower()
    agent = None
    if agent_slug:
        agent = (
            AgentDefinition.objects.select_related("model_config__provider", "model_config__credential")
            .filter(slug=agent_slug, enabled=True)
            .first()
        )
    if agent is None:
        agent = (
            AgentDefinition.objects.select_related("model_config__provider", "model_config__credential")
            .filter(enabled=True, purposes__slug=purpose)
            .order_by("-is_default", "slug")
            .first()
        )
    if not purpose:
        if agent:
            first_purpose = agent.purposes.order_by("slug").first()
            purpose = str(first_purpose.slug if first_purpose else "coding")
        else:
            purpose = "coding"
    purpose_obj = AgentPurpose.objects.filter(slug=purpose).first()
    purpose_preamble = str(getattr(purpose_obj, "preamble", "") or "")
    if agent:
        model_config = agent.model_config
        provider = model_config.provider
        credential = model_config.credential
        api_key = _resolve_model_api_key(provider.slug, credential)
        if not api_key:
            raise AiConfigError(
                f"No credential resolved for provider '{provider.slug}' on agent '{agent.slug}'."
            )
        return {
            "provider": provider.slug,
            "model_name": model_config.model_name,
            "api_key": api_key,
            "temperature": model_config.temperature,
            "max_tokens": model_config.max_tokens,
            "system_prompt": assemble_system_prompt(agent.system_prompt_text, purpose_preamble),
            "agent_slug": agent.slug,
            "purpose": purpose,
        }

    provider_slug = str(os.environ.get("XYN_DEFAULT_MODEL_PROVIDER") or "openai").strip().lower()
    model_name = str(os.environ.get("XYN_DEFAULT_MODEL_NAME") or "gpt-4o-mini").strip()
    provider = ModelProvider.objects.filter(slug=provider_slug).first() or ModelProvider.objects.filter(slug="openai").first()
    if provider:
        provider_slug = provider.slug

    api_key = _read_provider_env_key(provider_slug)
    if not api_key:
        raise AiConfigError(
            f"No agent configured for purpose '{purpose}' and no env key found for provider '{provider_slug}'."
        )

    return {
        "provider": provider_slug,
        "model_name": model_name,
        "api_key": api_key,
        "temperature": float(os.environ.get("XYN_DEFAULT_MODEL_TEMPERATURE") or 0.2),
        "max_tokens": int(os.environ.get("XYN_DEFAULT_MODEL_MAX_TOKENS") or 1200),
        "system_prompt": "",
        "agent_slug": None,
        "purpose": purpose,
    }


def invoke_model(*, resolved_config: Dict[str, Any], messages: List[Dict[str, str]]) -> Dict[str, Any]:
    provider = str(resolved_config.get("provider") or "").strip().lower()
    model_name = str(resolved_config.get("model_name") or "").strip()
    api_key = str(resolved_config.get("api_key") or "").strip()
    if not provider or not model_name or not api_key:
        raise AiInvokeError("provider/model/api_key are required")

    payload_messages = [msg for msg in _serialize_messages_for_provider(messages) if msg.get("role") != "system"]
    system_prompt = str(resolved_config.get("system_prompt") or "").strip()
    if system_prompt:
        payload_messages = [{"role": "system", "content": system_prompt}] + payload_messages

    temperature = resolved_config.get("temperature")
    max_tokens = resolved_config.get("max_tokens")

    if provider == "openai":
        body: Dict[str, Any] = {
            "model": model_name,
            "input": payload_messages,
        }
        if temperature is not None:
            body["temperature"] = temperature
        if max_tokens is not None:
            body["max_output_tokens"] = max_tokens
        response = requests.post(
            "https://api.openai.com/v1/responses",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=body,
            timeout=60,
        )
        if response.status_code >= 400:
            raise AiInvokeError(f"OpenAI error ({response.status_code}): {response.text[:300]}")
        data = response.json()
        content = str(data.get("output_text") or "")
        return {
            "content": content,
            "provider": provider,
            "model": model_name,
            "usage": data.get("usage") if isinstance(data.get("usage"), dict) else None,
            "raw": data,
        }

    if provider == "anthropic":
        system_text = ""
        anthro_messages: List[Dict[str, str]] = []
        for message in payload_messages:
            role = message.get("role")
            if role == "system":
                system_text = (system_text + "\n\n" + str(message.get("content") or "")).strip()
            else:
                anthro_messages.append({"role": role or "user", "content": str(message.get("content") or "")})
        body = {"model": model_name, "messages": anthro_messages, "max_tokens": int(max_tokens or 1200)}
        if system_text:
            body["system"] = system_text
        if temperature is not None:
            body["temperature"] = float(temperature)
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=body,
            timeout=60,
        )
        if response.status_code >= 400:
            raise AiInvokeError(f"Anthropic error ({response.status_code}): {response.text[:300]}")
        data = response.json()
        output_parts = data.get("content") if isinstance(data.get("content"), list) else []
        text_chunks: List[str] = []
        for part in output_parts:
            if isinstance(part, dict) and part.get("type") == "text":
                text_chunks.append(str(part.get("text") or ""))
        return {
            "content": "\n".join(chunk for chunk in text_chunks if chunk).strip(),
            "provider": provider,
            "model": model_name,
            "usage": data.get("usage") if isinstance(data.get("usage"), dict) else None,
            "raw": data,
        }

    if provider == "google":
        # Gemini API
        user_parts: List[Dict[str, Any]] = []
        for message in payload_messages:
            user_parts.append({"text": str(message.get("content") or "")})
        body = {
            "contents": [{"role": "user", "parts": user_parts}],
            "generationConfig": {
                "temperature": float(temperature if temperature is not None else 0.2),
                "maxOutputTokens": int(max_tokens or 1200),
            },
        }
        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}",
            headers={"Content-Type": "application/json"},
            json=body,
            timeout=60,
        )
        if response.status_code >= 400:
            raise AiInvokeError(f"Google error ({response.status_code}): {response.text[:300]}")
        data = response.json()
        candidates = data.get("candidates") if isinstance(data.get("candidates"), list) else []
        text = ""
        if candidates:
            content = candidates[0].get("content") if isinstance(candidates[0], dict) else {}
            parts = content.get("parts") if isinstance(content, dict) else []
            texts = [str(part.get("text") or "") for part in parts if isinstance(part, dict)]
            text = "\n".join(chunk for chunk in texts if chunk).strip()
        return {
            "content": text,
            "provider": provider,
            "model": model_name,
            "usage": None,
            "raw": data,
        }

    raise AiInvokeError(f"Unsupported provider '{provider}'")


def ensure_default_ai_seeds() -> None:
    provider_specs = [
        ("openai", "OpenAI", True),
        ("anthropic", "Anthropic", True),
        ("google", "Google", True),
    ]
    provider_map: Dict[str, ModelProvider] = {}
    for slug, name, enabled in provider_specs:
        provider, _ = ModelProvider.objects.get_or_create(slug=slug, defaults={"name": name, "enabled": enabled})
        provider_map[slug] = provider

    provider_slug = str(os.environ.get("XYN_DEFAULT_MODEL_PROVIDER") or "openai").strip().lower()
    model_name = str(os.environ.get("XYN_DEFAULT_MODEL_NAME") or "gpt-4o-mini").strip()
    provider = provider_map.get(provider_slug) or provider_map.get("openai")

    def _seed_bootstrap_credential(slug: str, provider_obj: Optional[ModelProvider]) -> Optional[ProviderCredential]:
        if not provider_obj:
            return None
        existing_default = (
            ProviderCredential.objects.filter(provider=provider_obj, is_default=True, enabled=True).order_by("-created_at").first()
        )
        if existing_default:
            return existing_default
        env_value = _read_provider_env_key(slug)
        if not env_value and slug == "openai":
            legacy = OpenAIConfig.objects.first()
            env_value = str(legacy.api_key if legacy else "").strip()
        if not env_value:
            return None
        name = "codex-bootstrap"
        existing_named = ProviderCredential.objects.filter(provider=provider_obj, name=name).first()
        if existing_named:
            if not existing_named.is_default:
                existing_named.is_default = True
                existing_named.enabled = True
                existing_named.save(update_fields=["is_default", "enabled", "updated_at"])
            return existing_named
        store = SecretStore.objects.filter(is_default=True).first()
        if not store:
            return ProviderCredential.objects.create(
                provider=provider_obj,
                name=name,
                auth_type="env_ref",
                env_var_name=PROVIDER_ENV_API_KEY.get(slug, [""])[0] or "",
                is_default=True,
                enabled=True,
            )
        logical = normalize_secret_logical_name(f"ai/{slug}/{name}/api_key")
        secret_ref = SecretRef.objects.filter(scope_kind="platform", scope_id__isnull=True, name=logical).first()
        if not secret_ref:
            secret_ref = SecretRef.objects.create(
                name=logical,
                scope_kind="platform",
                scope_id=None,
                store=store,
                external_ref="pending",
                type="secrets_manager",
                description=f"{slug} bootstrap AI API key",
            )
        try:
            external_ref, metadata = write_secret_value(
                store,
                logical_name=logical,
                scope_kind="platform",
                scope_id=None,
                scope_path_id=None,
                secret_ref_id=str(secret_ref.id),
                value=env_value,
                description=f"{slug} bootstrap AI API key",
            )
            secret_ref.external_ref = external_ref
            secret_ref.metadata_json = {**(secret_ref.metadata_json or {}), **metadata}
            secret_ref.save(update_fields=["external_ref", "metadata_json", "updated_at"])
            return ProviderCredential.objects.create(
                provider=provider_obj,
                name=name,
                auth_type="api_key",
                secret_ref=secret_ref,
                is_default=True,
                enabled=True,
            )
        except Exception:
            # Fall back to env_ref if store exists but isn't writable in this environment.
            return ProviderCredential.objects.create(
                provider=provider_obj,
                name=name,
                auth_type="env_ref",
                env_var_name=PROVIDER_ENV_API_KEY.get(slug, [""])[0] or "",
                is_default=True,
                enabled=True,
            )

    _seed_bootstrap_credential("openai", provider_map.get("openai"))
    _seed_bootstrap_credential("anthropic", provider_map.get("anthropic"))
    _seed_bootstrap_credential("google", provider_map.get("google"))

    default_model = None
    if provider:
        default_model = provider.model_configs.filter(model_name=model_name).order_by("created_at").first()
        if default_model is None:
            default_model = provider.model_configs.create(
                model_name=model_name,
                temperature=float(os.environ.get("XYN_DEFAULT_MODEL_TEMPERATURE") or 0.2),
                max_tokens=int(os.environ.get("XYN_DEFAULT_MODEL_MAX_TOKENS") or 1200),
                enabled=True,
            )

    coding, _ = AgentPurpose.objects.get_or_create(
        slug="coding",
        defaults={
            "name": "Coding",
            "description": "Code generation and development tasks",
            "status": "active",
            "enabled": True,
            "preamble": "Purpose: coding. Focus on production-ready implementation guidance.",
            "model_config": default_model,
        },
    )
    documentation, _ = AgentPurpose.objects.get_or_create(
        slug="documentation",
        defaults={
            "name": "Documentation",
            "description": "Documentation drafting and editing",
            "status": "active",
            "enabled": True,
            "preamble": "Purpose: documentation. Produce concise, accurate, publishable drafts.",
            "model_config": default_model,
        },
    )

    if not coding.name:
        coding.name = "Coding"
    if not coding.preamble:
        coding.preamble = "Purpose: coding. Focus on production-ready implementation guidance."
    if not coding.model_config_id and default_model:
        coding.model_config = default_model
    coding.save(update_fields=["name", "preamble", "model_config", "updated_at"])
    if not documentation.name:
        documentation.name = "Documentation"
    if not documentation.preamble:
        documentation.preamble = "Purpose: documentation. Produce concise, accurate, publishable drafts."
    if not documentation.model_config_id and default_model:
        documentation.model_config = default_model
    documentation.save(update_fields=["name", "preamble", "model_config", "updated_at"])

    assistant, _ = AgentDefinition.objects.get_or_create(
        slug="default-assistant",
        defaults={
            "name": "Xyn Default Assistant",
            "model_config": default_model,
            "system_prompt_text": DEFAULT_ASSISTANT_PROMPT,
            "is_default": True,
            "enabled": True,
        },
    )
    assistant.name = "Xyn Default Assistant"
    if default_model and not assistant.model_config_id:
        assistant.model_config = default_model
    assistant.system_prompt_text = DEFAULT_ASSISTANT_PROMPT
    assistant.is_default = True
    assistant.enabled = True
    assistant.save(update_fields=["name", "model_config", "system_prompt_text", "is_default", "enabled", "updated_at"])
    AgentDefinition.objects.exclude(id=assistant.id).filter(is_default=True).update(is_default=False)
    assistant.purposes.add(coding, documentation)
    # Remove the legacy bootstrap agent to keep a single canonical default assistant.
    AgentDefinition.objects.filter(slug="documentation-default").exclude(id=assistant.id).delete()
    AgentDefinition.objects.filter(name__iexact="Documentation Default").exclude(id=assistant.id).delete()
