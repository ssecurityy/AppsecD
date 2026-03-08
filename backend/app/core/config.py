"""Application configuration."""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """App settings from environment."""

    environment: str = "development"

    # Database (set via DATABASE_URL env var or .env file)
    database_url: str = ""

    # Redis (set via REDIS_URL env var or .env file)
    redis_url: str = ""

    # App secret. In production/staging this should always be set.
    secret_key: str = ""

    # App
    app_name: str = "AppSecD"
    debug: bool = False
    docs_enabled: bool = False  # Set True to expose /docs, /redoc, /openapi.json
    allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000,https://appsecd.com,https://www.appsecd.com,http://appsecd.com,http://www.appsecd.com"

    # Paths (used when storage_backend=local)
    payloads_path: str = "/opt/navigator/data/PayloadsAllTheThings"
    seclists_path: str = "/opt/navigator/data/SecLists"
    uploads_path: str = "/opt/navigator/data/uploads"

    # R2 / S3-compatible storage (when storage_backend=r2)
    storage_backend: str = "local"
    r2_endpoint_url: str = ""
    r2_bucket: str = ""
    r2_access_key_id: str = ""
    r2_secret_access_key: str = ""
    r2_region: str = "auto"

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
    claude_dast_max_api_calls: int = 300
    claude_dast_max_daily_scans: int = 50
    claude_dast_session_ttl_days: int = 30
    claude_dast_allowed_models: str = "claude-haiku-4-5,claude-sonnet-4-6,claude-opus-4-6"

    # GitHub OAuth for SAST repo integration
    github_oauth_client_id: str = ""
    github_oauth_client_secret: str = ""
    github_oauth_redirect_uri: str = ""

    # GitHub App for enterprise SaaS repo integration
    github_app_id: str = ""
    github_app_slug: str = ""
    github_app_client_id: str = ""
    github_app_client_secret: str = ""
    github_app_private_key: str = ""
    github_app_webhook_secret: str = ""
    github_app_name: str = "Navigator AppSec"

    # Enterprise: connection pool
    db_pool_size: int = 20
    db_max_overflow: int = 10

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
