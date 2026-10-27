"""Application configuration via environment variables."""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore", protected_namespaces=())

    # App
    app_name: str = "CyberSentinel AI"
    app_env: str = "development"
    secret_key: str = "change-me-to-a-random-256-bit-hex-string"
    access_token_expire_minutes: int = 60
    algorithm: str = "HS256"

    # Database
    database_url: str = "sqlite:///./cybersentinel.db"

    # CORS
    frontend_url: str = "http://localhost:5173"

    # Demo credentials
    demo_admin_username: str = "admin"
    demo_admin_password: str = "Admin@CyberSentinel2024"
    demo_analyst_username: str = "analyst"
    demo_analyst_password: str = "Analyst@CyberSentinel2024"

    # Optional LLM
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    # ML
    model_random_seed: int = 42
    anomaly_contamination: float = 0.05

    # Risk thresholds (0-100)
    risk_threshold_low: int = 25
    risk_threshold_medium: int = 50
    risk_threshold_high: int = 75

    # File upload limit (bytes)
    max_upload_size: int = 10 * 1024 * 1024  # 10 MB


@lru_cache
def get_settings() -> Settings:
    return Settings()
