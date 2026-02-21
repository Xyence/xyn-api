import re
from typing import Any, Dict, List, Tuple


def normalize_provider(provider_slug: str) -> str:
    return str(provider_slug or "").strip().lower()


def _is_openai_gpt5_model(model_name: str) -> bool:
    return bool(re.match(r"^gpt-5($|-)", str(model_name or "").strip().lower()))


def compute_effective_params(
    provider: str,
    model_name: str,
    base_params: Dict[str, Any],
    invocation_mode: str = "default",
) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    normalized_provider = normalize_provider(provider)
    effective: Dict[str, Any] = {}
    warnings: List[Dict[str, str]] = []

    for key, value in (base_params or {}).items():
        if value is not None:
            effective[key] = value

    if normalized_provider == "openai" and _is_openai_gpt5_model(model_name):
        for param in ("temperature", "top_p", "logprobs"):
            if param in effective:
                effective.pop(param, None)
                warnings.append(
                    {
                        "param": param,
                        "reason": "unsupported_by_model",
                        "detail": (
                            f"OpenAI {model_name} does not accept {param} in {invocation_mode} mode; "
                            "the parameter was omitted."
                        ),
                    }
                )

    return effective, warnings

