"""Vultr Serverless Inference, used only to fill fixed schemas and to explain results.

Every call asks for JSON matching a schema (response_format json_schema). There is
no tool calling: the model can't act, it can only fill fields that code checks.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from openai import AsyncOpenAI

BASE_URL = "https://api.vultrinference.com/v1"
EXTRACT_MODEL = "qwen3.8-flash-next"
EXPLAIN_MODEL = "glm-5.3-flash"
FALLBACK_MODEL = "glm-5.3"
GUARD_MODEL = "nemotron-3.5-content-safety"


class LLMError(Exception):
    """The model couldn't give a usable answer. Callers fall back to rules or to "unknown"."""


_client: Optional[AsyncOpenAI] = None


def client() -> AsyncOpenAI:
    global _client
    if _client is None:
        key = os.environ.get("VULTR_INFERENCE_KEY")
        if not key:
            raise LLMError("VULTR_INFERENCE_KEY is not set")
        _client = AsyncOpenAI(base_url=BASE_URL, api_key=key, timeout=30, max_retries=1)
    return _client


async def structured(*, system: str, user: str, schema_name: str, schema: dict,
                     model: str = EXTRACT_MODEL, tries: int = 2) -> dict:
    """JSON that matches the schema, trying the main model twice and then the fallback once."""
    errors = []
    for m in [model] * tries + [FALLBACK_MODEL]:
        try:
            r = await client().chat.completions.create(
                model=m,
                temperature=0,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                response_format={"type": "json_schema",
                                 "json_schema": {"name": schema_name, "strict": True, "schema": schema}},
            )
            data = json.loads(r.choices[0].message.content or "")
        except LLMError:
            raise
        except Exception as e:  # network, API and JSON errors all mean "try again"
            errors.append(f"{m}: {type(e).__name__}")
            continue
        if isinstance(data, dict):
            return data
        errors.append(f"{m}: answer was not a JSON object")
    raise LLMError("; ".join(errors))
