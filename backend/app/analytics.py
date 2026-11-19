from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import Index, case, func, literal, select, union_all
from sqlalchemy.orm import Session, aliased

from app.audit import asset_events
from app.inventory import DB, Asset
from app.scan_models import JobStatus, ScanJob, ScanResult, Service, utc

router = APIRouter(prefix="/api/analytics", tags=["analytics"])
analytics_indexes = (
    Index("analytics_job_created", ScanJob.created_at),
    Index("analytics_job_started", ScanJob.started_at),
    Index("analytics_job_finished", ScanJob.completed_at),
    Index("analytics_check_time", ScanResult.checked_at),
)


@dataclass(frozen=True)
class Period:
    start: date
    end: date

    def includes(self, field):
        return field.between(
            datetime.combine(self.start, time.min), datetime.combine(self.end, time.max)
        )


def parse_period(
    start: Annotated[
        date | None, Query(description="First UTC date, inclusive")
    ] = None,
    end: Annotated[date | None, Query(description="Last UTC date, inclusive")] = None,
) -> Period:
    end = end or datetime.now(UTC).date()
    start = start or end - timedelta(days=min(29, end.toordinal() - 1))
    if start > end or (end - start).days > 365:
        raise HTTPException(
            422, "Choose an ordered UTC date range of at most 366 days."
        )
    return Period(start, end)


Range = Annotated[Period, Depends(parse_period)]


class AvailabilityCounts(BaseModel):
    reachable: int = 0
    unreachable: int = 0
    unknown: int = 0


class ChangeCounts(BaseModel):
    newly_reachable: int = 0
    became_unreachable: int = 0


class Metrics(BaseModel):
    assets: int
    asset_status: AvailabilityCounts
    approved_services: int
    completed_jobs: int
    failed_jobs: int
    cancelled_jobs: int
    service_status: AvailabilityCounts
    changes: ChangeCounts


class Daily(ChangeCounts):
    day: date
    created: int = 0
    started: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0


class RecentJob(BaseModel):
    id: int
    status: JobStatus
    created_at: datetime
    completed_at: datetime | None
    check_count: int


class ConnectivityChange(BaseModel):
    id: int
    job_id: int
    asset_id: int
    asset_name: str
    service_name: str
    before: Literal["reachable", "unreachable"]
    after: Literal["reachable", "unreachable"]
    checked_at: datetime


class ActivityEvent(BaseModel):
    source_id: int
    kind: Literal[
        "job_created",
        "job_started",
        "job_completed",
        "job_cancelled",
        "job_failed",
        "asset_created",
        "asset_deleted",
        "newly_reachable",
        "became_unreachable",
    ]
    occurred_at: datetime
    job_id: int | None
    asset_id: int | None
    description: str


class Timeline(BaseModel):
    events: list[ActivityEvent]
    next_offset: int | None


class Dashboard(BaseModel):
    start: date
    end: date
    metrics: Metrics
    daily: list[Daily]
    recent_jobs: list[RecentJob]
    latest_changes: list[ConnectivityChange]


def completed_results(period: Period):
    return (
        select(ScanResult)
        .join(ScanJob)
        .where(ScanJob.status == "completed", period.includes(ScanResult.checked_at))
    )


def changes_query(period: Period):
    prior = aliased(ScanResult)
    prior_job = aliased(ScanJob)
    previous = (
        select(prior.status)
        .join(prior_job, prior.job_id == prior_job.id)
        .where(
            prior_job.status == "completed",
            prior.id < ScanResult.id,
            prior.asset_id == ScanResult.asset_id,
            prior.service_id == ScanResult.service_id,
            prior.address_revision == ScanResult.address_revision,
        )
        .order_by(prior.id.desc())
        .limit(1)
        .correlate(ScanResult)
        .scalar_subquery()
    )
    observed = (
        completed_results(period)
        .with_only_columns(
            ScanResult.id,
            ScanResult.job_id,
            ScanResult.asset_id,
            ScanResult.asset_name,
            ScanResult.service_name,
            ScanResult.status.label("after"),
            ScanResult.checked_at,
            previous.label("before"),
            maintain_column_froms=True,
        )
        .where(ScanResult.status.in_(("reachable", "unreachable")))
        .subquery()
    )
    return (
        select(observed)
        .where(
            observed.c.before.in_(("reachable", "unreachable")),
            observed.c.before != observed.c.after,
        )
        .subquery()
    )


def job_outcomes(period: Period):
    return (
        select(ScanJob.status, func.count())
        .where(period.includes(ScanJob.completed_at))
        .group_by(ScanJob.status)
    )


def metrics(db: Session, period: Period, changes) -> Metrics:
    assets = dict(
        db.execute(select(Asset.status, func.count()).group_by(Asset.status)).all()
    )
    results = (
        completed_results(period)
        .with_only_columns(ScanResult.status, func.count(), maintain_column_froms=True)
        .group_by(ScanResult.status)
    )
    service_status = dict(db.execute(results).all())
    outcomes = dict(db.execute(job_outcomes(period)).all())
    shifts = dict(
        db.execute(
            select(changes.c.after, func.count()).group_by(changes.c.after)
        ).all()
    )
    return Metrics(
        assets=sum(assets.values()),
        asset_status=AvailabilityCounts(**assets),
        approved_services=db.scalar(
            select(func.count()).select_from(Service).where(Service.active)
        ),
        completed_jobs=outcomes.get("completed", 0),
        failed_jobs=outcomes.get("failed", 0),
        cancelled_jobs=outcomes.get("cancelled", 0),
        service_status=AvailabilityCounts(**service_status),
        changes=ChangeCounts(
            newly_reachable=shifts.get("reachable", 0),
            became_unreachable=shifts.get("unreachable", 0),
        ),
    )


def daily_counts(db: Session, period: Period, changes) -> list[Daily]:
    days = {
        day.isoformat(): Daily(day=day)
        for day in (
            period.start + timedelta(days=offset)
            for offset in range((period.end - period.start).days + 1)
        )
    }
    created = func.date(ScanJob.created_at)
    started = func.date(ScanJob.started_at)
    finished = func.date(ScanJob.completed_at)
    shifted = func.date(changes.c.checked_at)
    for day, count in db.execute(
        select(created, func.count())
        .where(period.includes(ScanJob.created_at))
        .group_by(created)
    ):
        days[day].created = count
    for day, count in db.execute(
        select(started, func.count())
        .where(period.includes(ScanJob.started_at))
        .group_by(started)
    ):
        days[day].started = count
    for day, status, count in db.execute(
        select(finished, ScanJob.status, func.count())
        .where(
            period.includes(ScanJob.completed_at),
            ScanJob.status.in_(("completed", "failed", "cancelled")),
        )
        .group_by(finished, ScanJob.status)
    ):
        setattr(days[day], status, count)
    for day, status, count in db.execute(
        select(shifted, changes.c.after, func.count()).group_by(
            shifted, changes.c.after
        )
    ):
        setattr(
            days[day],
            "newly_reachable" if status == "reachable" else "became_unreachable",
            count,
        )
    return list(days.values())


def recent_jobs_query(period: Period):
    return (
        select(ScanJob)
        .where(
            period.includes(ScanJob.created_at)
            | period.includes(ScanJob.started_at)
            | period.includes(ScanJob.completed_at)
        )
        .order_by(
            func.coalesce(
                ScanJob.completed_at, ScanJob.started_at, ScanJob.created_at
            ).desc(),
            ScanJob.id.desc(),
        )
    )


@router.get("/overview")
def overview(db: DB, period: Range, response: Response) -> Dashboard:
    """Read current inventory totals and historical aggregates for the selected UTC dates."""
    response.headers["Cache-Control"] = "no-store"
    db.connection().exec_driver_sql("BEGIN")
    changes = changes_query(period)
    recent = db.scalars(recent_jobs_query(period).limit(8))
    latest = db.execute(
        select(changes)
        .order_by(changes.c.checked_at.desc(), changes.c.id.desc())
        .limit(8)
    ).mappings()
    return Dashboard(
        start=period.start,
        end=period.end,
        metrics=metrics(db, period, changes),
        daily=daily_counts(db, period, changes),
        recent_jobs=[
            RecentJob(
                id=job.id,
                status=job.status,
                created_at=utc(job.created_at),
                completed_at=utc(job.completed_at),
                check_count=job.check_count,
            )
            for job in recent
        ],
        latest_changes=[
            ConnectivityChange(**{**row, "checked_at": utc(row.checked_at)})
            for row in latest
        ],
    )


def job_event(period: Period, timestamp, kind, description: str):
    return select(
        ScanJob.id.label("source_id"),
        kind.label("kind"),
        timestamp.label("occurred_at"),
        ScanJob.id.label("job_id"),
        literal(None).label("asset_id"),
        literal(description).label("description"),
    ).where(period.includes(timestamp))


@router.get("/timeline")
def timeline(
    db: DB,
    period: Range,
    response: Response,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> Timeline:
    """Read recorded activity newest first, with a continuation offset when available."""
    response.headers["Cache-Control"] = "no-store"
    changes = changes_query(period)
    terminal = case(
        (ScanJob.status == "completed", "job_completed"),
        (ScanJob.status == "cancelled", "job_cancelled"),
        else_="job_failed",
    )
    events = union_all(
        job_event(
            period, ScanJob.created_at, literal("job_created"), "Scan job created"
        ),
        job_event(
            period, ScanJob.started_at, literal("job_started"), "Scan job started"
        ),
        job_event(period, ScanJob.completed_at, terminal, "Scan job finished").where(
            ScanJob.status.in_(("completed", "cancelled", "failed"))
        ),
        select(
            asset_events.c.id,
            asset_events.c.kind,
            asset_events.c.occurred_at,
            literal(None),
            asset_events.c.asset_id,
            asset_events.c.asset_name,
        ).where(period.includes(asset_events.c.occurred_at)),
        select(
            changes.c.id,
            case(
                (changes.c.after == "reachable", "newly_reachable"),
                else_="became_unreachable",
            ),
            changes.c.checked_at,
            changes.c.job_id,
            changes.c.asset_id,
            changes.c.asset_name + " / " + changes.c.service_name,
        ),
    ).subquery()
    rows = (
        db.execute(
            select(events)
            .order_by(
                events.c.occurred_at.desc(), events.c.kind, events.c.source_id.desc()
            )
            .offset(offset)
            .limit(limit + 1)
        )
        .mappings()
        .all()
    )
    return Timeline(
        events=[
            ActivityEvent(**{**row, "occurred_at": utc(row.occurred_at)})
            for row in rows[:limit]
        ],
        next_offset=offset + limit
        if len(rows) > limit and offset + limit <= 100_000
        else None,
    )
