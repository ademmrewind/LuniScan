from datetime import date, datetime

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select

from app.analytics import ConnectivityChange, Period, changes_query
from app.inventory import (
    DB,
    AssetID,
    AssetObservation,
    AssetView,
    DiscoveryResult,
    find_asset,
)
from app.scan_models import JobStatus, ResultView, ScanJob, ScanResult, ServiceView, utc
from app.scans import result_view

router = APIRouter(prefix="/api/assets", tags=["asset intelligence"])


class AssetJob(BaseModel):
    id: int
    status: JobStatus
    created_at: datetime


class IntelligenceView(BaseModel):
    asset: AssetView
    last_connectivity_check: datetime | None
    monitored_services: list[ServiceView]
    latest_results: list[ResultView]
    availability_history: list[DiscoveryResult]
    service_history: list[ResultView]
    recent_jobs: list[AssetJob]
    changes: list[ConnectivityChange]


@router.get("/{asset_id}/intelligence")
def intelligence(asset_id: AssetID, db: DB) -> IntelligenceView:
    """Read recent persisted observations and approved services used for this asset."""
    asset = find_asset(db, asset_id)
    observations = db.scalars(
        select(AssetObservation)
        .where(AssetObservation.asset_id == asset_id)
        .order_by(AssetObservation.id.desc())
        .limit(30)
    )
    availability = [
        DiscoveryResult(
            ip_address=row.ip_address,
            status=row.status,
            checked_at=utc(row.checked_at),
            port=row.port,
            error_category=row.error_category,
            duration_ms=row.duration_ms,
        )
        for row in observations
    ]
    current = (
        ScanResult.asset_id == asset.id,
        ScanResult.address_revision == asset.address_revision,
    )
    latest_ids = (
        select(func.max(ScanResult.id)).where(*current).group_by(ScanResult.service_id)
    )
    latest = [
        result_view(row)
        for row in db.scalars(
            select(ScanResult)
            .where(ScanResult.id.in_(latest_ids))
            .order_by(ScanResult.id.desc())
            .limit(30)
        )
    ]
    from app.scan_models import Service

    services = [
        ServiceView.model_validate(row)
        for row in db.scalars(
            select(Service)
            .where(
                Service.active,
                Service.id.in_(select(ScanResult.service_id).where(*current)),
            )
            .order_by(Service.name)
            .limit(30)
        )
    ]
    history = [
        result_view(row)
        for row in db.scalars(
            select(ScanResult)
            .where(ScanResult.asset_id == asset_id)
            .order_by(ScanResult.id.desc())
            .limit(30)
        )
    ]
    jobs = db.scalars(
        select(ScanJob)
        .where(
            ScanJob.id.in_(
                select(ScanResult.job_id).where(ScanResult.asset_id == asset_id)
            )
        )
        .order_by(ScanJob.id.desc())
        .limit(10)
    )
    shifts = changes_query(Period(date.min, date.max), asset_id=asset_id)
    changes = db.execute(
        select(shifts).order_by(shifts.c.id.desc()).limit(10)
    ).mappings()
    checked = [row.checked_at for row in latest]
    if asset.last_checked is not None:
        checked.append(utc(asset.last_checked))
    return IntelligenceView(
        asset=AssetView.model_validate(asset),
        last_connectivity_check=max(checked, default=None),
        monitored_services=services,
        latest_results=latest,
        availability_history=availability,
        service_history=history,
        recent_jobs=[
            AssetJob(id=job.id, status=job.status, created_at=utc(job.created_at))
            for job in jobs
        ],
        changes=[
            ConnectivityChange(**{**row, "checked_at": utc(row.checked_at)})
            for row in changes
        ],
    )
