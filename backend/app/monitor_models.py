from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, StrictBool, field_validator, model_validator
from sqlalchemy import JSON, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.inventory import Base, InputModel
from app.monitor_engine import Certificate, Health, Outcome, Protocol
from app.scope import parse_address

AlertStatus = Literal["active", "acknowledged", "resolved"]


class MonitorProfile(Base):
    __tablename__ = "monitor_profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(index=True)
    ip_address: Mapped[str] = mapped_column(String(45))
    name: Mapped[str] = mapped_column(String(80))
    protocol: Mapped[str] = mapped_column(String(6))
    port: Mapped[int]
    hostname: Mapped[str | None] = mapped_column(String(253))
    timeout_ms: Mapped[int]
    path: Mapped[str] = mapped_column(String(128))
    status_min: Mapped[int]
    status_max: Mapped[int]
    expected_content: Mapped[str | None] = mapped_column(String(128))
    enabled: Mapped[bool]
    archived: Mapped[bool] = mapped_column(default=False)
    revision: Mapped[int] = mapped_column(default=0)
    health: Mapped[str] = mapped_column(String(12), default="unknown")
    certificate_state: Mapped[str | None] = mapped_column(String(24))
    duration_ms: Mapped[float | None]
    last_checked: Mapped[datetime | None] = mapped_column(DateTime)
    last_success: Mapped[datetime | None] = mapped_column(DateTime)
    last_failure: Mapped[datetime | None] = mapped_column(DateTime)


class MonitorCheck(Base):
    __tablename__ = "monitor_checks"
    id: Mapped[int] = mapped_column(primary_key=True)
    profile_id: Mapped[int] = mapped_column(
        ForeignKey("monitor_profiles.id"), index=True
    )
    checked_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    health: Mapped[str] = mapped_column(String(12))
    previous_health: Mapped[str | None] = mapped_column(String(12))
    duration_ms: Mapped[float]
    http_status: Mapped[int | None]
    certificate_state: Mapped[str | None] = mapped_column(String(24))
    result: Mapped[dict] = mapped_column(JSON)


class MonitorAlert(Base):
    __tablename__ = "monitor_alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    profile_id: Mapped[int] = mapped_column(
        ForeignKey("monitor_profiles.id"), index=True
    )
    kind: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(12))
    status: Mapped[str] = mapped_column(String(15))
    created_at: Mapped[datetime] = mapped_column(DateTime)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)


Index(
    "one_open_monitor_alert",
    MonitorAlert.profile_id,
    MonitorAlert.kind,
    unique=True,
    sqlite_where=MonitorAlert.resolved_at.is_(None),
)


class ProfileInput(InputModel):
    asset_id: int = Field(strict=True, gt=0, le=2**63 - 1)
    ip_address: str = Field(max_length=45)
    name: str = Field(min_length=1, max_length=80, pattern=r"^[^\x00-\x1f\x7f]+$")
    protocol: Protocol
    port: int = Field(strict=True, ge=1, le=65535)
    hostname: str | None = Field(
        default=None,
        max_length=253,
        pattern=r"^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$",
    )
    timeout_ms: int = Field(default=1500, strict=True, ge=250, le=3000)
    path: str = Field(default="/", max_length=128, pattern=r"^/[a-zA-Z0-9/_.-]*$")
    status_min: int = Field(default=200, strict=True, ge=200, le=599)
    status_max: int = Field(default=299, strict=True, ge=200, le=599)
    expected_content: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: StrictBool = True
    confirm_approval: StrictBool

    @field_validator("ip_address")
    @classmethod
    def canonical_ip(cls, value: str) -> str:
        return str(parse_address(value))

    @model_validator(mode="after")
    def validate_check(self):
        if not self.confirm_approval:
            raise ValueError("Explicit endpoint approval is required.")
        if self.status_min > self.status_max:
            raise ValueError("The expected status range is reversed.")
        if "//" in self.path or any(
            part in {".", ".."} for part in self.path.split("/")
        ):
            raise ValueError("Use a simple absolute path.")
        if self.protocol not in ("http", "https") and (
            self.path != "/" or self.expected_content
        ):
            raise ValueError("Path and expected content apply only to HTTP checks.")
        return self


class ProfileView(BaseModel):
    id: int
    asset_id: int
    asset_name: str | None
    ip_address: str
    name: str
    protocol: Protocol
    port: int
    hostname: str | None
    timeout_ms: int
    path: str
    status_min: int
    status_max: int
    checks_content: bool
    enabled: bool
    archived: bool
    health: Health
    certificate_state: str | None
    duration_ms: float | None
    last_checked: datetime | None
    last_success: datetime | None
    last_failure: datetime | None


class CheckView(Outcome):
    id: int
    profile_id: int
    checked_at: datetime
    previous_health: Health | None


class AlertView(BaseModel):
    id: int
    profile_id: int
    asset_id: int
    profile_name: str
    kind: str
    severity: Literal["warning", "critical"]
    status: AlertStatus
    created_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None


class ProfileDetail(BaseModel):
    profile: ProfileView
    history: list[CheckView]
    certificate: Certificate | None
    alerts: list[AlertView]
