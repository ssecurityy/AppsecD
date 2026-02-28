"""LLM model registry — OpenAI, Anthropic, Google Gemini. Cursor-style full list."""

# (provider, model_id, label)
LLM_MODELS = [
    # OpenAI
    ("openai", "gpt-4o-mini", "GPT-4o mini (fast, cheap)"),
    ("openai", "gpt-4o", "GPT-4o (better quality)"),
    ("openai", "gpt-4o-2024-11-20", "GPT-4o (Nov 2024)"),
    ("openai", "gpt-4-turbo", "GPT-4 Turbo"),
    ("openai", "gpt-4-turbo-preview", "GPT-4 Turbo Preview"),
    ("openai", "gpt-4", "GPT-4"),
    ("openai", "gpt-4.1", "GPT-4.1 (flagship)"),
    ("openai", "gpt-4.1-mini", "GPT-4.1 mini (fast)"),
    ("openai", "gpt-4.1-nano", "GPT-4.1 nano (budget)"),
    ("openai", "gpt-3.5-turbo", "GPT-3.5 Turbo"),
    ("openai", "o1", "O1 (reasoning)"),
    ("openai", "o1-mini", "O1 mini (reasoning)"),
    # Anthropic Claude
    ("anthropic", "claude-opus-4-6", "Claude Opus 4.6 (latest)"),
    ("anthropic", "claude-sonnet-4-6", "Claude Sonnet 4.6"),
    ("anthropic", "claude-haiku-4-5-20251001", "Claude Haiku 4.5"),
    ("anthropic", "claude-opus-4-1", "Claude Opus 4.1"),
    ("anthropic", "claude-opus-4", "Claude Opus 4"),
    ("anthropic", "claude-sonnet-4", "Claude Sonnet 4"),
    ("anthropic", "claude-3-7-sonnet-latest", "Claude 3.7 Sonnet"),
    ("anthropic", "claude-3-5-haiku-latest", "Claude 3.5 Haiku"),
    ("anthropic", "claude-3-5-sonnet-latest", "Claude 3.5 Sonnet"),
    ("anthropic", "claude-3-opus-latest", "Claude 3 Opus"),
    # Google Gemini
    ("google", "gemini-2.5-pro-preview", "Gemini 2.5 Pro Preview"),
    ("google", "gemini-2.5-flash-preview", "Gemini 2.5 Flash Preview"),
    ("google", "gemini-2.5-pro", "Gemini 2.5 Pro"),
    ("google", "gemini-2.5-flash", "Gemini 2.5 Flash"),
    ("google", "gemini-2.5-flash-lite", "Gemini 2.5 Flash Lite"),
    ("google", "gemini-2.0-flash", "Gemini 2.0 Flash"),
    ("google", "gemini-2.0-flash-lite", "Gemini 2.0 Flash Lite"),
    ("google", "gemini-1.5-pro", "Gemini 1.5 Pro"),
    ("google", "gemini-1.5-flash", "Gemini 1.5 Flash"),
    ("google", "gemini-1.5-flash-8b", "Gemini 1.5 Flash 8B"),
]

VALID_MODELS = {(p, m) for p, m, _ in LLM_MODELS}


def get_provider_for_model(provider: str | None, model: str) -> str:
    """Resolve provider from stored config or infer from model id."""
    if provider:
        return provider
    # Infer from model prefix
    if model.startswith("gpt-") or model.startswith("o1"):
        return "openai"
    if model.startswith("claude-"):
        return "anthropic"
    if model.startswith("gemini-"):
        return "google"
    return "openai"
