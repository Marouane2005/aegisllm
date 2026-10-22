from functools import lru_cache
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "AegisLLM"
    ENVIRONMENT: str = Field(default="production")
    DEBUG: bool = False
    ALLOWED_ORIGINS: str = "https://aegis.example.com"
    ALLOW_REGISTRATION: bool = True

    POSTGRES_USER: str
    POSTGRES_PASSWORD: SecretStr
    POSTGRES_HOST: str = "db"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "aegisllm"

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:"
            f"{self.POSTGRES_PASSWORD.get_secret_value()}@"
            f"{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    REDIS_URL: str = "redis://redis:6379/0"

    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24
    FERNET_MASTER_KEY: SecretStr

    ALLOWED_UPSTREAM_HOSTS: str = "api.openai.com,api.anthropic.com"
    PROXY_REQUEST_TIMEOUT_SEC: int = 120
    MAX_REQUEST_BODY_BYTES: int = 2 * 1024 * 1024

    RATE_LIMIT_PER_MINUTE: int = 60
    CLEANUP_HOUR_UTC: int = 3


@lru_cache
def get_settings() -> Settings:
    return Settings()
