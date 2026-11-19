from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LUNISCAN_", env_file=".env", hide_input_in_errors=True
    )

    database_url: str = "sqlite:///./luniscan.db"
    approved_scope: list[str] = Field(default=["127.0.0.1", "::1"], max_length=64)
    approved_service_port: int = Field(default=8443, ge=1, le=65535)
    discovery_limit: int = Field(default=4, ge=1, le=8)

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        try:
            url = make_url(value)
        except ArgumentError:
            raise ValueError("Use a local SQLite file URL.") from None
        if (
            url.drivername not in {"sqlite", "sqlite+pysqlite"}
            or any(part is not None for part in (url.host, url.port, url.username, url.password))
            or not url.database
            or url.database == ":memory:"
            or url.database.lower().startswith("file:")
            or url.database.startswith(("//", "\\"))
            or url.query
        ):
            raise ValueError("Use a local SQLite file URL.")
        return value
