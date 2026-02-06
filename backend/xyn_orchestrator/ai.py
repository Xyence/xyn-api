import json
from typing import Any, Dict, Tuple

from openai import OpenAI

from .models import OpenAIConfig


ARTICLE_SCHEMA = {
    "name": "article_draft",
    "description": "Draft article content for publishing on a web page.",
    "schema": {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "summary": {"type": "string"},
            "body_html": {"type": "string"},
        },
        "required": ["title", "summary", "body_html"],
        "additionalProperties": False,
    },
    "strict": True,
}


def _extract_text(response: Any) -> str:
    if hasattr(response, "output_text") and response.output_text:
        return response.output_text
    try:
        output = response.output[0]
        content = output.content[0]
        return content.text
    except Exception:
        return ""


def generate_article_draft(prompt: str, config: OpenAIConfig, model: str | None = None) -> Tuple[Dict[str, Any], Any]:
    client = OpenAI(api_key=config.api_key)
    chosen_model = model or config.default_model
    response = client.responses.create(
        model=chosen_model,
        input=[
            {"role": "system", "content": config.system_instructions},
            {"role": "user", "content": prompt},
        ],
        text={"format": {"type": "json_schema", **ARTICLE_SCHEMA}},
    )
    output_text = _extract_text(response)
    data = json.loads(output_text) if output_text else {}
    return data, response
