"""Application configuration."""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """App settings from environment."""

    # Database
    database_url: str = "postgresql+asyncpg://navigator:navigator_secure_password@127.0.0.1:5433/navigator"

    # Redis
    redis_url: str = "redis://127.0.0.1:6379/1"

    # App
    app_name: str = "VAPT Navigator"
    debug: bool = False
    allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    # Paths
    payloads_path: str = "/opt/navigator/data/PayloadsAllTheThings"
    seclists_path: str = "/opt/navigator/data/SecLists"
    uploads_path: str = "/opt/navigator/data/uploads"

    # JIRA integration (optional)
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = ""

    # AI Assist — LLM mode (optional; when set, uses OpenAI instead of rule-based)
    openai_api_key: str = ""

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
