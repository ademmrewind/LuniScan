from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy import JSON, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.inventory import Base, InputModel
from app.scope import Availability, ProbeError

JobStatus = Literal["pending", "running", "completed", "failed", "cancelled"]
Change = Literal["newly_reachable", "became_unreachable", "unchanged", "inconclusive"]
Port = Annotated[int, Field(strict=True, ge=1, le=65535)]
SelectionID = Annotated[int, Field(strict=True, gt=0, le=2**63 - 1)]


def now() -> datetime:
    return datetime.now(UTC)


def utc(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=UTC) if value else None


class Service(Base):
    __tablename__ = "approved_services"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    port: Mapped[int] = mapped_column(unique=True)
    active: Mapped[bool] = mapped_column(default=True)
    approval_revision: Mapped[int] = mapped_column(default=0)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(String(12))
    created_at: Mapped[datetime] = mapped_column(DateTime)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    asset_count: Mapped[int]
    check_count: Mapped[int]
    done_count: Mapped[int] = mapped_column(default=0)
    plan: Mapped[list[dict]] = mapped_column(JSON)
    failure: Mapped[str | None] = mapped_column(String(40))


Index(
    "one_running_scan_job",
    ScanJob.status,
    unique=True,
    sqlite_where=ScanJob.status == "running",
)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    asset_id: Mapped[int]
    asset_name: Mapped[str] = mapped_column(String(100))
    ip_address: Mapped[str] = mapped_column(String(45))
    address_revision: Mapped[int]
    service_id: Mapped[int]
    service_name: Mapped[str] = mapped_column(String(80))
    port: Mapped[int]
    status: Mapped[str] = mapped_column(String(12))
    error_category: Mapped[str | None] = mapped_column(String(24))
    checked_at: Mapped[datetime] = mapped_column(DateTime)


Index("scan_result_endpoint", ScanResult.asset_id, ScanResult.service_id, ScanResult.id)


class ServiceInput(InputModel):
    name: str = Field(min_length=1, max_length=80, pattern=r"^[^\x00-\x1f\x7f]+$")
    port: Port
    confirm_approval: StrictBool


class ServiceView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    port: Port
    active: bool


class Confirmation(InputModel):
    confirm_approval: StrictBool


class JobInput(Confirmation):
    asset_ids: list[SelectionID] = Field(min_length=1, max_length=8)
    service_ids: list[SelectionID] = Field(min_length=1, max_length=4)


class JobSummary(BaseModel):
    reachable: int = 0
    unreachable: int = 0
    unknown: int = 0


class ResultView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    job_id: int
    asset_id: int
    asset_name: str
    ip_address: str
    service_id: int
    service_name: str
    port: Port
    status: Availability
    error_category: ProbeError | None
    checked_at: datetime


class HistoryView(ResultView):
    duration_seconds: float


class ComparisonView(BaseModel):
    result: ResultView
    previous: ResultView | None
    change: Change


class PlannedCheck(BaseModel):
    asset_id: int
    asset_name: str
    ip_address: str
    address_revision: int
    service_id: int
    service_revision: int
    service_name: str
    port: Port


class JobView(BaseModel):
    id: int
    status: JobStatus
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    asset_count: int
    check_count: int
    done_count: int
    progress: int
    summary: JobSummary
    failure: str | None


class JobDetail(JobView):
    plan: list[PlannedCheck]
    results: list[ResultView]
