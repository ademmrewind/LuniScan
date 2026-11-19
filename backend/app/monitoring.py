import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import case, func, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.inventory import DB, ApprovedScope, Asset, AssetID, InputModel, find_asset
from app.monitor_engine import (
    CertificateState,
    CheckTarget,
    Health,
    Outcome,
    Protocol,
    observe,
)
from app.monitor_models import (
    AlertStatus,
    AlertView,
    CheckView,
    MonitorAlert,
    MonitorCheck,
    MonitorProfile,
    ProfileDetail,
    ProfileInput,
    ProfileView,
)
from app.scan_models import now, utc

router = APIRouter(prefix="/api/monitoring", tags=["service monitoring profiles"])
logger = logging.getLogger("uvicorn.error.luniscan.monitoring")
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=100000)]


class EmptyAction(InputModel):
    pass


def profile_row(db: Session, profile_id: int) -> MonitorProfile:
    profile = db.get(MonitorProfile, profile_id)
    if profile is None:
        raise HTTPException(404, "Monitoring profile not found.")
    return profile


def profile_view(profile: MonitorProfile, asset_name: str | None) -> ProfileView:
    values = {
        name: getattr(profile, name)
        for name in ProfileView.model_fields
        if name not in {"asset_name", "checks_content"}
    }
    for name in ("last_checked", "last_success", "last_failure"):
        values[name] = utc(values[name])
    return ProfileView(
        **values,
        asset_name=asset_name,
        checks_content=profile.expected_content is not None,
    )


def check_view(check: MonitorCheck) -> CheckView:
    return CheckView(
        **check.result,
        id=check.id,
        profile_id=check.profile_id,
        checked_at=utc(check.checked_at),
        previous_health=check.previous_health,
    )


def alert_view(alert: MonitorAlert, profile: MonitorProfile) -> AlertView:
    return AlertView(
        id=alert.id,
        profile_id=profile.id,
        asset_id=profile.asset_id,
        profile_name=profile.name,
        kind=alert.kind,
        severity=alert.severity,
        status=alert.status,
        created_at=utc(alert.created_at),
        acknowledged_at=utc(alert.acknowledged_at),
        resolved_at=utc(alert.resolved_at),
    )


def confirm_asset(db: Session, asset_id: int, address: str) -> Asset:
    asset = find_asset(db, asset_id)
    if asset.ip_address != address:
        raise HTTPException(
            409, "The destination does not match the registered asset address."
        )
    return asset


@router.get("/profiles")
def profiles(
    db: DB,
    asset_id: AssetID | None = None,
    protocol: Protocol | None = None,
    health: Health | None = None,
    certificate_state: CertificateState | None = None,
    profile_id: AssetID | None = None,
    offset: Offset = 0,
    limit: Limit = 50,
) -> list[ProfileView]:
    statement = select(MonitorProfile, Asset.display_name).outerjoin(
        Asset, Asset.id == MonitorProfile.asset_id
    )
    statement = statement.where(MonitorProfile.archived.is_(False))
    for column, value in (
        (MonitorProfile.asset_id, asset_id),
        (MonitorProfile.protocol, protocol),
        (MonitorProfile.health, health),
        (MonitorProfile.certificate_state, certificate_state),
        (MonitorProfile.id, profile_id),
    ):
        if value is not None:
            statement = statement.where(column == value)
    return [
        profile_view(row, asset_name)
        for row, asset_name in db.execute(
            statement.order_by(MonitorProfile.id.desc()).offset(offset).limit(limit)
        )
    ]


@router.post("/profiles", status_code=201)
def create_profile(payload: ProfileInput, db: DB, scope: ApprovedScope) -> ProfileView:
    """Register one explicitly approved asset, protocol and TCP port."""
    scope.require(payload.ip_address)
    asset = confirm_asset(db, payload.asset_id, payload.ip_address)
    profile = MonitorProfile(**payload.model_dump(exclude={"confirm_approval"}))
    db.add(profile)
    db.commit()
    logger.info("Monitoring profile %s created", profile.id)
    return profile_view(profile, asset.display_name)


@router.put("/profiles/{profile_id}")
def edit_profile(
    profile_id: AssetID, payload: ProfileInput, db: DB, scope: ApprovedScope
) -> ProfileView:
    profile = profile_row(db, profile_id)
    if profile.archived:
        raise HTTPException(409, "The profile is archived.")
    scope.require(payload.ip_address)
    asset = confirm_asset(db, payload.asset_id, payload.ip_address)
    for field in ("asset_id", "ip_address", "protocol", "port"):
        if getattr(profile, field) != getattr(payload, field):
            raise HTTPException(
                409, "Create a new profile for a different endpoint or protocol."
            )
    values = payload.model_dump(exclude={"confirm_approval"})
    if "expected_content" not in payload.model_fields_set:
        values.pop("expected_content")
    updated = db.execute(
        update(MonitorProfile)
        .where(
            MonitorProfile.id == profile_id,
            MonitorProfile.archived.is_(False),
            MonitorProfile.revision == profile.revision,
        )
        .values(**values, revision=MonitorProfile.revision + 1)
    )
    if not updated.rowcount:
        raise HTTPException(409, "The profile changed. Refresh and retry.")
    db.commit()
    logger.info("Monitoring profile %s updated", profile_id)
    return profile_view(profile, asset.display_name)


@router.delete("/profiles/{profile_id}", status_code=204)
def archive_profile(profile_id: AssetID, db: DB) -> None:
    profile_row(db, profile_id)
    db.execute(
        update(MonitorProfile)
        .where(MonitorProfile.id == profile_id)
        .values(
            archived=True,
            enabled=False,
            revision=MonitorProfile.revision + 1,
        )
    )
    db.commit()
    logger.info("Monitoring profile %s archived", profile_id)


def history_rows(
    db: Session, profile_id: int, offset: int, limit: int
) -> list[CheckView]:
    return [
        check_view(item)
        for item in db.scalars(
            select(MonitorCheck)
            .where(MonitorCheck.profile_id == profile_id)
            .order_by(MonitorCheck.id.desc())
            .offset(offset)
            .limit(limit)
        )
    ]


@router.get("/profiles/{profile_id}/history")
def history(
    profile_id: AssetID, db: DB, offset: Offset = 0, limit: Limit = 50
) -> list[CheckView]:
    profile_row(db, profile_id)
    return history_rows(db, profile_id, offset, limit)


@router.get("/profiles/{profile_id}")
def details(profile_id: AssetID, db: DB) -> ProfileDetail:
    profile = profile_row(db, profile_id)
    asset = db.get(Asset, profile.asset_id)
    results = history_rows(db, profile_id, 0, 30)
    cert_row = db.scalar(
        select(MonitorCheck)
        .where(
            MonitorCheck.profile_id == profile_id,
            MonitorCheck.certificate_state.is_not(None),
        )
        .order_by(MonitorCheck.id.desc())
        .limit(1)
    )
    alerts = db.scalars(
        select(MonitorAlert)
        .where(MonitorAlert.profile_id == profile_id)
        .order_by(MonitorAlert.id.desc())
        .limit(30)
    )
    return ProfileDetail(
        profile=profile_view(profile, asset.display_name if asset else None),
        history=results,
        certificate=check_view(cert_row).certificate if cert_row else None,
        alerts=[alert_view(item, profile) for item in alerts],
    )


def update_alerts(
    db: Session,
    profile: MonitorProfile,
    result: Outcome,
    previous: list[str],
    timestamp,
    critical_days: int,
) -> None:
    conditions = {}
    recovered = set()
    if result.health == "unreachable" and previous[:1] == ["healthy"]:
        conditions["became_unreachable"] = "critical"
    if result.health == "degraded":
        conditions["health_degraded"] = "warning"
    if (
        result.health != "healthy"
        and len(previous) == 2
        and all(item != "healthy" for item in previous)
    ):
        conditions["repeated_failures"] = "critical"
    if result.health == "healthy":
        recovered.update(("became_unreachable", "health_degraded", "repeated_failures"))
    cert = result.certificate
    if cert is not None:
        if cert.state == "expiring_soon":
            conditions["certificate_expiring"] = (
                "critical"
                if cert.expires_at
                and cert.expires_at - cert.inspected_at <= timedelta(days=critical_days)
                else "warning"
            )
        if cert.state == "expired":
            conditions["certificate_expired"] = "critical"
        if cert.verified is False:
            conditions["certificate_verification"] = "critical"
        if cert.verified and cert.state in {"valid", "expiring_soon"}:
            recovered.update(("certificate_expired", "certificate_verification"))
            if cert.state == "valid":
                recovered.add("certificate_expiring")
    current = {
        item.kind: item
        for item in db.scalars(
            select(MonitorAlert).where(
                MonitorAlert.profile_id == profile.id,
                MonitorAlert.resolved_at.is_(None),
            )
        )
    }
    for kind, severity in conditions.items():
        if kind in current:
            current[kind].severity = severity
        else:
            db.add(
                MonitorAlert(
                    profile_id=profile.id,
                    kind=kind,
                    severity=severity,
                    status="active",
                    created_at=timestamp,
                )
            )
    for kind in recovered & current.keys():
        current[kind].status = "resolved"
        current[kind].resolved_at = timestamp


@dataclass(frozen=True)
class AuthorizedCheck:
    ip_address: str
    revision: int
    target: CheckTarget


def planned(engine: Engine, profile_id: int) -> AuthorizedCheck:
    with Session(engine) as db:
        profile = profile_row(db, profile_id)
        if profile.archived or not profile.enabled:
            raise HTTPException(409, "Monitoring is disabled for this profile.")
        confirm_asset(db, profile.asset_id, profile.ip_address)
        return AuthorizedCheck(
            profile.ip_address,
            profile.revision,
            CheckTarget(
                profile.protocol,
                profile.port,
                profile.hostname,
                profile.timeout_ms,
                profile.path,
                profile.status_min,
                profile.status_max,
                profile.expected_content,
            ),
        )


def store_check(
    engine: Engine, profile_id: int, revision: int, result: Outcome, critical_days: int
) -> CheckView:
    timestamp = now()
    with Session(engine) as db:
        profile = profile_row(db, profile_id)
        previous = list(
            db.scalars(
                select(MonitorCheck.health)
                .where(MonitorCheck.profile_id == profile_id)
                .order_by(MonitorCheck.id.desc())
                .limit(2)
            )
        )
        updates = {
            "health": result.health,
            "duration_ms": result.duration_ms,
            "last_checked": timestamp,
        }
        updates["last_success" if result.health == "healthy" else "last_failure"] = (
            timestamp
        )
        cert_state = result.certificate.state if result.certificate else None
        if cert_state is not None:
            updates["certificate_state"] = cert_state
        changed = db.execute(
            update(MonitorProfile)
            .where(
                MonitorProfile.id == profile_id,
                MonitorProfile.revision == revision,
                MonitorProfile.enabled.is_(True),
                MonitorProfile.archived.is_(False),
            )
            .values(**updates)
        )
        if not changed.rowcount:
            raise HTTPException(409, "Profile approval changed during the check.")
        if result.outcome == "connected":
            db.execute(
                update(Asset)
                .where(
                    Asset.id == profile.asset_id, Asset.ip_address == profile.ip_address
                )
                .values(last_seen=timestamp)
            )
        check = MonitorCheck(
            profile_id=profile_id,
            checked_at=timestamp,
            health=result.health,
            previous_health=previous[0] if previous else None,
            duration_ms=result.duration_ms,
            http_status=result.http_status,
            certificate_state=cert_state,
            result=result.model_dump(mode="json"),
        )
        db.add(check)
        update_alerts(db, profile, result, previous, timestamp, critical_days)
        db.commit()
        logger.info("Monitoring profile %s checked: %s", profile_id, result.health)
        return check_view(check)


@router.post("/profiles/{profile_id}/check", status_code=201)
async def manual_check(
    profile_id: AssetID, payload: EmptyAction, request: Request, scope: ApprovedScope
) -> CheckView:
    """Run a single manual check, using the shared connection rate and concurrency limits."""
    engine = request.app.state.engine
    settings = request.app.state.config
    with scope.operation():
        approval = await run_in_threadpool(planned, engine, profile_id)
        address = scope.reserve(approval.ip_address)
        result = await observe(address, approval.target, settings.tls_warn_days)
        return await run_in_threadpool(
            store_check,
            engine,
            profile_id,
            approval.revision,
            result,
            settings.tls_critical_days,
        )


@router.get("/alerts")
def alerts(
    db: DB,
    status: AlertStatus | None = None,
    profile_id: AssetID | None = None,
    severity: Annotated[str | None, Query(pattern="^(warning|critical)$")] = None,
    offset: Offset = 0,
    limit: Limit = 50,
) -> list[AlertView]:
    statement = select(MonitorAlert, MonitorProfile).join(MonitorProfile)
    for column, value in (
        (MonitorAlert.status, status),
        (MonitorAlert.profile_id, profile_id),
        (MonitorAlert.severity, severity),
    ):
        if value is not None:
            statement = statement.where(column == value)
    return [
        alert_view(alert, profile)
        for alert, profile in db.execute(
            statement.order_by(MonitorAlert.id.desc()).offset(offset).limit(limit)
        )
    ]


@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: AssetID, payload: EmptyAction, db: DB) -> AlertView:
    alert = db.get(MonitorAlert, alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found.")
    db.execute(
        update(MonitorAlert)
        .where(MonitorAlert.id == alert_id, MonitorAlert.status == "active")
        .values(status="acknowledged", acknowledged_at=now())
    )
    db.commit()
    return alert_view(alert, profile_row(db, alert.profile_id))


class DayMetrics(BaseModel):
    day: str
    healthy: int
    failed: int
    mean_http_ms: float | None


class Summary(BaseModel):
    profiles: dict[Health, int]
    certificates: dict[str, int]
    alerts: dict[str, int]
    daily: list[DayMetrics]
    recent: list[CheckView]
    transitions: list[CheckView]


def summarize(db: Session) -> Summary:
    counts = dict(
        db.execute(
            select(MonitorProfile.health, func.count())
            .where(
                MonitorProfile.enabled,
                MonitorProfile.archived.is_(False),
            )
            .group_by(MonitorProfile.health)
        ).all()
    )
    certs = dict(
        db.execute(
            select(MonitorProfile.certificate_state, func.count())
            .where(
                MonitorProfile.enabled,
                MonitorProfile.archived.is_(False),
                MonitorProfile.certificate_state.is_not(None),
            )
            .group_by(MonitorProfile.certificate_state)
        ).all()
    )
    alert_counts = dict(
        db.execute(
            select(MonitorAlert.severity, func.count())
            .where(MonitorAlert.resolved_at.is_(None))
            .group_by(MonitorAlert.severity)
        ).all()
    )
    day = func.date(MonitorCheck.checked_at)
    grouped = db.execute(
        select(
            day,
            func.sum(case((MonitorCheck.health == "healthy", 1), else_=0)),
            func.count(),
            func.avg(
                case((MonitorCheck.http_status.is_not(None), MonitorCheck.duration_ms))
            ),
        )
        .where(MonitorCheck.checked_at >= now() - timedelta(days=30))
        .group_by(day)
        .order_by(day)
    )
    recent = select(MonitorCheck).order_by(MonitorCheck.id.desc()).limit(8)
    changes = recent.where(MonitorCheck.previous_health != MonitorCheck.health)
    return Summary(
        profiles=counts,
        certificates=certs,
        alerts=alert_counts,
        daily=[
            DayMetrics(
                day=date,
                healthy=healthy,
                failed=total - healthy,
                mean_http_ms=round(mean, 2) if mean is not None else None,
            )
            for date, healthy, total, mean in grouped
        ],
        recent=[check_view(row) for row in db.scalars(recent)],
        transitions=[check_view(row) for row in db.scalars(changes)],
    )


@router.get("/summary")
def summary(db: DB) -> Summary:
    return summarize(db)
