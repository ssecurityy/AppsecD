"""LLM models service — auto-fetch latest from provider APIs, merge with built-in + custom."""
import time
from typing import Optional

from app.core.llm_models import LLM_MODELS

# In-memory cache: {provider: [(model_id, label), ...]}
_API_MODELS_CACHE: dict[str, list[tuple[str, str]]] = {}
_API_CACHE_EXPIRY: dict[str, float] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour


def _fetch_openai_models(api_key: str) -> list[tuple[str, str]]:
    """Fetch chat models from OpenAI API."""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        r = client.models.list()
        out = []
        for m in r.data:
            mid = getattr(m, "id", None) or str(m)
            if not mid or not isinstance(mid, str):
                continue
            # Only chat/completion models
            if any(x in mid for x in ["gpt-", "o1", "o3"]):
                out.append((mid, mid))
        return sorted(out, key=lambda x: x[0])
    except Exception:
        return []


def _fetch_anthropic_models(api_key: str) -> list[tuple[str, str]]:
    """Fetch models from Anthropic API."""
    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)
        # Anthropic doesn't have a public models.list; use known models
        return []
    except Exception:
        return []


def _fetch_google_models(api_key: str) -> list[tuple[str, str]]:
    """Fetch models from Google Generative AI."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        out = []
        for m in genai.list_models():
            if "generateContent" in (m.supported_generation_methods or []):
                out.append((m.name.replace("models/", ""), m.display_name or m.name))
        return sorted(out, key=lambda x: x[0])
    except Exception:
        return []


def fetch_latest_models(
    openai_key: Optional[str] = None,
    anthropic_key: Optional[str] = None,
    google_key: Optional[str] = None,
    custom_models: Optional[list[tuple[str, str, str]]] = None,
    force_refresh: bool = False,
) -> list[tuple[str, str, str]]:
    """
    Return merged models: built-in + custom + API-fetched (when keys available).
    Returns [(provider, model_id, label), ...]
    """
    now = time.time()
    builtin = {(p, m): l for p, m, l in LLM_MODELS}
    custom = custom_models or []

    result: dict[tuple[str, str], str] = dict(builtin)

    # OpenAI — auto-fetch if key available
    if openai_key and (force_refresh or now > _API_CACHE_EXPIRY.get("openai", 0)):
        try:
            api_models = _fetch_openai_models(openai_key)
            _API_MODELS_CACHE["openai"] = api_models
            _API_CACHE_EXPIRY["openai"] = now + CACHE_TTL_SECONDS
        except Exception:
            api_models = _API_MODELS_CACHE.get("openai", [])
    else:
        api_models = _API_MODELS_CACHE.get("openai", [])

    for mid, label in api_models:
        result[("openai", mid)] = label

    # Google — auto-fetch if key available
    if google_key and (force_refresh or now > _API_CACHE_EXPIRY.get("google", 0)):
        try:
            api_models = _fetch_google_models(google_key)
            _API_MODELS_CACHE["google"] = api_models
            _API_CACHE_EXPIRY["google"] = now + CACHE_TTL_SECONDS
        except Exception:
            api_models = _API_MODELS_CACHE.get("google", [])
    else:
        api_models = _API_MODELS_CACHE.get("google", [])

    for mid, label in api_models:
        result[("google", mid)] = label

    # Merge custom (override built-in labels if same model)
    for p, m, l in custom:
        result[(p, m)] = l

    out = [(p, m, result[(p, m)]) for (p, m) in sorted(result.keys())]
    return out


def is_valid_provider_model(provider: str, model: str) -> bool:
    """Accept known providers and any model id (future-proof)."""
    if provider not in ("openai", "anthropic", "google"):
        return False
    if not model or not model.strip():
        return False
    # Allow any model for known providers (future models like gpt-5, claude-5)
    return True
