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
    app_name: str = "AppSecD"
    debug: bool = False
    docs_enabled: bool = False  # Set True to expose /docs, /redoc, /openapi.json
    allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000,https://appsecd.com,https://www.appsecd.com,http://appsecd.com,http://www.appsecd.com"

    # Paths
    payloads_path: str = "/opt/navigator/data/PayloadsAllTheThings"
    seclists_path: str = "/opt/navigator/data/SecLists"
    uploads_path: str = "/opt/navigator/data/uploads"

    # JIRA integration (optional)
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = ""

    # AI Assist — LLM mode (optional; when set, uses LLM instead of rule-based)
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    google_api_key: str = ""

    # Notifications (optional)
    slack_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "navigator@localhost"
    smtp_tls: bool = True
    notification_emails: str = ""  # Comma-separated emails for critical alerts
    webhook_url: str = ""  # Generic outgoing webhook
    cache_enabled: bool = True

    # Claude DAST — AI-powered scanning
    claude_dast_enabled: bool = True
    claude_dast_default_model: str = "claude-sonnet-4-6"
    claude_dast_max_cost_per_scan: float = 20.0
    claude_dast_max_api_calls: int = 200
    claude_dast_max_daily_scans: int = 50
    claude_dast_session_ttl_days: int = 30
    claude_dast_allowed_models: str = "claude-haiku-4-5,claude-sonnet-4-6,claude-opus-4-6"

    # Enterprise: connection pool
    db_pool_size: int = 20
    db_max_overflow: int = 10

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
