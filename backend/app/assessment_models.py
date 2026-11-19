from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, StrictBool
from sqlalchemy import JSON, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.assessment_rules import Observation, Severity
from app.inventory import Base, InputModel
from app.monitor_engine import Certificate

AssessmentStatus = Literal["pending", "running", "completed", "failed", "cancelled"]
FindingStatus = Literal["open", "acknowledged", "resolved", "inconclusive"]


class Assessment(Base):
    __tablename__ = "security_assessments"
    id: Mapped[int] = mapped_column(primary_key=True)
    profile_id: Mapped[int] = mapped_column(
        ForeignKey("monitor_profiles.id"), index=True
    )
    asset_id: Mapped[int] = mapped_column(index=True)
    asset_name: Mapped[str] = mapped_column(String(100))
    service_name: Mapped[str] = mapped_column(String(80))
    ip_address: Mapped[str] = mapped_column(String(45))
    port: Mapped[int]
    protocol: Mapped[str] = mapped_column(String(5))
    path: Mapped[str] = mapped_column(String(128))
    profile_revision: Mapped[int]
    authorized: Mapped[bool]
    status: Mapped[str] = mapped_column(String(12))
    created_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    failure: Mapped[str | None] = mapped_column(String(32))
    evidence: Mapped[dict | None] = mapped_column(JSON)
    summary: Mapped[dict | None] = mapped_column(JSON)


class Finding(Base):
    __tablename__ = "security_findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    profile_id: Mapped[int] = mapped_column(
        ForeignKey("monitor_profiles.id"), index=True
    )
    asset_id: Mapped[int] = mapped_column(index=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("security_assessments.id"))
    rule: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(15))
    severity: Mapped[str] = mapped_column(String(15), index=True)
    snapshot: Mapped[dict] = mapped_column(JSON)
    first_observed: Mapped[datetime] = mapped_column(DateTime)
    last_observed: Mapped[datetime] = mapped_column(DateTime)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)


class FindingObservation(Base):
    __tablename__ = "security_finding_observations"
    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("security_assessments.id"), index=True
    )
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("security_findings.id"), index=True
    )
    snapshot: Mapped[dict] = mapped_column(JSON)


Index(
    "security_assessment_active",
    Assessment.authorized,
    unique=True,
    sqlite_where=Assessment.status.in_(("pending", "running")),
)
Index(
    "security_finding_unresolved",
    Finding.profile_id,
    Finding.rule,
    unique=True,
    sqlite_where=Finding.status.in_(("open", "acknowledged")),
)


class StartAssessment(InputModel):
    asset_id: int = Field(strict=True, gt=0, le=2**63 - 1)
    profile_id: int = Field(strict=True, gt=0, le=2**63 - 1)
    confirm_authorization: StrictBool


class Coverage(BaseModel):
    assessed: int
    inconclusive: int
    not_applicable: int
    counts: dict[Severity, int]


class AssessmentView(BaseModel):
    id: int
    profile_id: int
    asset_id: int
    asset_name: str
    service_name: str
    ip_address: str
    port: int
    protocol: str
    path: str
    authorized: bool
    status: AssessmentStatus
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    failure: str | None
    summary: Coverage | None


class AssessmentObservation(Observation):
    finding_id: int | None


class AssessmentEvidence(BaseModel):
    http_status: int | None
    connection: str
    error: str | None
    duration_ms: float
    certificate: Certificate | None
    tls_version: str | None
    tls_cipher: str | None
    tls_assessment: (
        Literal[
            "not_applicable",
            "verification_failure",
            "configuration_warning",
            "observed_secure",
            "insufficient_evidence",
        ]
        | None
    ) = None


class AssessmentDetail(AssessmentView):
    evidence: AssessmentEvidence | None
    observations: list[AssessmentObservation]


class FindingView(Observation):
    id: int
    profile_id: int
    asset_id: int
    asset_name: str
    service_name: str
    assessment_id: int
    status: FindingStatus
    first_observed: datetime
    last_observed: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None


class FindingHistory(BaseModel):
    assessment_id: int
    completed_at: datetime | None
    observation: Observation


class FindingDetail(FindingView):
    history: list[FindingHistory]


class SecuritySummary(BaseModel):
    assessment_count: int
    assets_with_open_findings: int
    open_counts: dict[Severity, int]
    recent: list[AssessmentView]
    trends: list[dict[str, int | str]]
