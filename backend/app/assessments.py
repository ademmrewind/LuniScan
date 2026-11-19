import asyncio
import logging
from collections import Counter
from dataclasses import replace
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from sqlalchemy import func, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.assessment_models import (
    Assessment,
    AssessmentDetail,
    AssessmentObservation,
    AssessmentStatus,
    AssessmentView,
    Coverage,
    Finding,
    FindingDetail,
    FindingHistory,
    FindingObservation,
    FindingStatus,
    FindingView,
    SecuritySummary,
    StartAssessment,
)
from app.assessment_rules import Observation, Severity, header_rules, tls_rules
from app.inventory import DB, ApprovedScope, AssetID
from app.monitor_engine import Outcome, ResponseEvidence, observe
from app.monitoring import EmptyAction, confirm_asset, planned, profile_row
from app.scan_models import now, utc
from app.scope import Scope

router = APIRouter(prefix="/api/security", tags=["security configuration assessments"])
logger = logging.getLogger("uvicorn.error.luniscan.assessment")
Offset = Annotated[int, Query(ge=0, le=100000)]
Limit = Annotated[int, Query(ge=1, le=100)]
OPEN = ("open", "acknowledged")
ACTIVE = ("pending", "running")


def assessment_row(db: Session, assessment_id: int) -> Assessment:
    row = db.get(Assessment, assessment_id)
    if row is None:
        raise HTTPException(404, "Assessment not found.")
    return row


def assessment_view(row: Assessment) -> AssessmentView:
    fields = {name: getattr(row, name) for name in AssessmentView.model_fields}
    for name in ("created_at", "started_at", "completed_at"):
        fields[name] = utc(fields[name])
    return AssessmentView(**fields)


def assessment_detail(db: Session, row: Assessment) -> AssessmentDetail:
    observations = db.scalars(
        select(FindingObservation)
        .where(FindingObservation.assessment_id == row.id)
        .order_by(FindingObservation.id)
    )
    return AssessmentDetail(
        **assessment_view(row).model_dump(),
        evidence=row.evidence,
        observations=[
            AssessmentObservation(**item.snapshot, finding_id=item.finding_id)
            for item in observations
        ],
    )


def finding_view(row: Finding, related: Assessment) -> FindingView:
    return FindingView(
        **row.snapshot,
        id=row.id,
        profile_id=row.profile_id,
        asset_id=row.asset_id,
        asset_name=related.asset_name,
        service_name=related.service_name,
        assessment_id=row.assessment_id,
        status=row.status,
        first_observed=utc(row.first_observed),
        last_observed=utc(row.last_observed),
        acknowledged_at=utc(row.acknowledged_at),
        resolved_at=utc(row.resolved_at),
    )


def recover_assessments(engine: Engine) -> None:
    with Session(engine) as db, db.begin():
        db.execute(
            update(Assessment)
            .where(Assessment.status.in_(ACTIVE))
            .values(status="failed", failure="interrupted", completed_at=now())
        )


def transition(
    engine: Engine, assessment_id: int, values: dict, expected: tuple[str, ...]
) -> bool:
    with Session(engine) as db, db.begin():
        changed = db.execute(
            update(Assessment)
            .where(Assessment.id == assessment_id, Assessment.status.in_(expected))
            .values(**values)
        ).rowcount
    return bool(changed)


def read_plan(engine: Engine, assessment_id: int):
    with Session(engine) as db:
        row = assessment_row(db, assessment_id)
        if row.status != "running":
            return None
        profile_id, revision = row.profile_id, row.profile_revision
    approval = planned(engine, profile_id)
    if approval.revision != revision or approval.target.protocol not in (
        "http",
        "https",
    ):
        raise HTTPException(409, "Profile authorization changed.")
    return approval


def save_observations(
    db: Session, row: Assessment, observations: list[Observation], timestamp
) -> None:
    unresolved = {
        item.rule: item
        for item in db.scalars(
            select(Finding).where(
                Finding.profile_id == row.profile_id, Finding.status.in_(OPEN)
            )
        )
    }
    for observation in observations:
        snapshot = observation.model_dump(mode="json")
        finding = unresolved.get(observation.rule)
        if observation.evaluation == "finding":
            if finding is None:
                finding = Finding(
                    profile_id=row.profile_id,
                    asset_id=row.asset_id,
                    assessment_id=row.id,
                    rule=observation.rule,
                    status="open",
                    severity=observation.severity,
                    snapshot=snapshot,
                    first_observed=timestamp,
                    last_observed=timestamp,
                )
                db.add(finding)
                db.flush()
            else:
                finding.assessment_id = row.id
                finding.snapshot = snapshot
                finding.severity = observation.severity
                finding.last_observed = timestamp
        elif observation.evaluation == "pass" and finding is not None:
            finding.status = "resolved"
            finding.resolved_at = timestamp
        db.add(
            FindingObservation(
                assessment_id=row.id,
                finding_id=finding.id if finding else None,
                snapshot=snapshot,
            )
        )


def finish_assessment(
    engine: Engine,
    assessment_id: int,
    outcome: Outcome,
    evidence: ResponseEvidence,
    observations: list[Observation],
) -> None:
    timestamp = now()
    with Session(engine) as db, db.begin():
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        row = assessment_row(db, assessment_id)
        if row.status != "running":
            return
        profile = profile_row(db, row.profile_id)
        if (
            profile.revision != row.profile_revision
            or profile.archived
            or not profile.enabled
        ):
            raise HTTPException(409, "Profile authorization changed.")
        confirm_asset(db, row.asset_id, row.ip_address)
        coverage = Counter(item.evaluation for item in observations)
        counts = Counter(
            item.severity for item in observations if item.evaluation == "finding"
        )
        row.summary = Coverage(
            assessed=coverage["pass"] + coverage["finding"],
            inconclusive=coverage["inconclusive"],
            not_applicable=coverage["not_applicable"],
            counts=dict(counts),
        ).model_dump()
        row.evidence = {
            "http_status": outcome.http_status,
            "connection": outcome.outcome,
            "error": outcome.error,
            "duration_ms": outcome.duration_ms,
            "certificate": outcome.certificate.model_dump(mode="json")
            if outcome.certificate
            else None,
            "tls_version": evidence.tls_version,
            "tls_cipher": evidence.tls_cipher,
            "tls_assessment": classify_tls(row.protocol, outcome, observations),
        }
        row.status = "completed"
        row.completed_at = timestamp
        save_observations(db, row, observations, timestamp)
    logger.info("Security assessment %s completed", assessment_id)


def classify_tls(
    protocol: str, outcome: Outcome, observations: list[Observation]
) -> str:
    if protocol != "https":
        return "not_applicable"
    if outcome.certificate is not None and outcome.certificate.verified is False:
        return "verification_failure"
    evaluations = {item.evaluation for item in observations if item.category == "tls"}
    if "finding" in evaluations:
        return "configuration_warning"
    if evaluations == {"pass"}:
        return "observed_secure"
    return "insufficient_evidence"


async def run_assessment(
    engine: Engine, scope: Scope, assessment_id: int, warn_days: int
) -> None:
    active = await run_in_threadpool(
        transition,
        engine,
        assessment_id,
        {"status": "running", "started_at": now()},
        ("pending",),
    )
    if not active:
        return
    failure = "internal_error"
    try:
        with scope.operation(wait_for_cooldown=True):
            await asyncio.sleep(scope.cooldown_remaining())
            approval = await run_in_threadpool(read_plan, engine, assessment_id)
            if approval is None:
                return
            address = scope.reserve(approval.ip_address)
            target = replace(approval.target, expected_content=None)
            evidence = ResponseEvidence()
            outcome = await observe(address, target, warn_days, evidence)
            observations = header_rules(target.protocol, outcome, evidence) + tls_rules(
                target.protocol, outcome, evidence
            )
            await run_in_threadpool(
                finish_assessment,
                engine,
                assessment_id,
                outcome,
                evidence,
                observations,
            )
        return
    except HTTPException as error:
        failure = {
            429: "network_busy",
            403: "scope_denied",
            409: "approval_changed",
            404: "approval_changed",
        }.get(error.status_code, "check_rejected")
    except Exception:
        logger.error("Security assessment %s worker failed", assessment_id)
    await run_in_threadpool(
        transition,
        engine,
        assessment_id,
        {"status": "failed", "failure": failure, "completed_at": now()},
        ACTIVE,
    )


@router.post("/assessments", status_code=202)
def start(
    payload: StartAssessment,
    tasks: BackgroundTasks,
    request: Request,
    db: DB,
    scope: ApprovedScope,
) -> AssessmentView:
    """Authorize and start a single bounded assessment of an existing HTTP or HTTPS profile."""
    if not payload.confirm_authorization:
        raise HTTPException(422, "Explicit assessment authorization is required.")
    profile = profile_row(db, payload.profile_id)
    if (
        profile.archived
        or not profile.enabled
        or profile.protocol not in ("http", "https")
    ):
        raise HTTPException(422, "Select an enabled HTTP or HTTPS profile.")
    if profile.asset_id != payload.asset_id:
        raise HTTPException(409, "The profile does not belong to the selected asset.")
    scope.require(profile.ip_address)
    asset = confirm_asset(db, profile.asset_id, profile.ip_address)
    row = Assessment(
        profile_id=profile.id,
        asset_id=asset.id,
        asset_name=asset.display_name,
        service_name=profile.name,
        ip_address=profile.ip_address,
        port=profile.port,
        protocol=profile.protocol,
        path=profile.path,
        profile_revision=profile.revision,
        authorized=True,
        status="pending",
        created_at=now(),
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(429, "A security assessment is already active.") from None
    logger.info("Security assessment %s authorized", row.id)
    tasks.add_task(
        run_assessment,
        db.get_bind(),
        scope,
        row.id,
        request.app.state.config.tls_warn_days,
    )
    return assessment_view(row)


@router.get("/assessments")
def assessments(
    db: DB,
    asset_id: AssetID | None = None,
    status: AssessmentStatus | None = None,
    offset: Offset = 0,
    limit: Limit = 25,
) -> list[AssessmentView]:
    statement = select(Assessment)
    if asset_id is not None:
        statement = statement.where(Assessment.asset_id == asset_id)
    if status is not None:
        statement = statement.where(Assessment.status == status)
    return [
        assessment_view(row)
        for row in db.scalars(
            statement.order_by(Assessment.id.desc()).offset(offset).limit(limit)
        )
    ]


@router.get("/assessments/{assessment_id}")
def detail(assessment_id: AssetID, db: DB) -> AssessmentDetail:
    return assessment_detail(db, assessment_row(db, assessment_id))


@router.post("/assessments/{assessment_id}/cancel")
def cancel(assessment_id: AssetID, payload: EmptyAction, db: DB) -> AssessmentView:
    row = assessment_row(db, assessment_id)
    changed = db.execute(
        update(Assessment)
        .where(Assessment.id == assessment_id, Assessment.status.in_(ACTIVE))
        .values(status="cancelled", completed_at=now())
    )
    db.commit()
    if not changed.rowcount and row.status != "cancelled":
        raise HTTPException(409, "The assessment has already finished.")
    logger.info("Security assessment %s cancelled", assessment_id)
    return assessment_view(row)


@router.get("/findings")
def findings(
    db: DB,
    asset_id: AssetID | None = None,
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    unresolved: bool = False,
    offset: Offset = 0,
    limit: Limit = 25,
) -> list[FindingView]:
    statement = select(Finding, Assessment).join(
        Assessment, Finding.assessment_id == Assessment.id
    )
    for column, value in (
        (Finding.asset_id, asset_id),
        (Finding.severity, severity),
        (Finding.status, status),
    ):
        if value is not None:
            statement = statement.where(column == value)
    if unresolved:
        statement = statement.where(Finding.status.in_(OPEN))
    return [
        finding_view(row, assessment)
        for row, assessment in db.execute(
            statement.order_by(Finding.id.desc()).offset(offset).limit(limit)
        )
    ]


def finding_row(db: Session, finding_id: int) -> Finding:
    item = db.get(Finding, finding_id)
    if item is None:
        raise HTTPException(404, "Finding not found.")
    return item


@router.get("/findings/{finding_id}")
def finding_detail(
    finding_id: AssetID, db: DB, offset: Offset = 0, limit: Limit = 25
) -> FindingDetail:
    item = finding_row(db, finding_id)
    statement = (
        select(FindingObservation, Assessment)
        .join(Assessment)
        .where(FindingObservation.finding_id == finding_id)
        .order_by(FindingObservation.id.desc())
        .offset(offset)
        .limit(limit)
    )
    return FindingDetail(
        **finding_view(item, assessment_row(db, item.assessment_id)).model_dump(),
        history=[
            FindingHistory(
                assessment_id=assessment.id,
                completed_at=utc(assessment.completed_at),
                observation=Observation.model_validate(observation.snapshot),
            )
            for observation, assessment in db.execute(statement)
        ],
    )


@router.post("/findings/{finding_id}/acknowledge")
def acknowledge(finding_id: AssetID, payload: EmptyAction, db: DB) -> FindingView:
    row = finding_row(db, finding_id)
    db.execute(
        update(Finding)
        .where(Finding.id == finding_id, Finding.status == "open")
        .values(status="acknowledged", acknowledged_at=now())
    )
    db.commit()
    return finding_view(row, assessment_row(db, row.assessment_id))


@router.get("/summary")
def summary(db: DB, asset_id: AssetID | None = None) -> SecuritySummary:
    assessment_selection = (
        (Assessment.asset_id == asset_id,) if asset_id is not None else ()
    )
    finding_selection = (Finding.asset_id == asset_id,) if asset_id is not None else ()
    active = (Finding.status.in_(OPEN), *finding_selection)
    recent = db.scalars(
        select(Assessment)
        .where(*assessment_selection)
        .order_by(Assessment.id.desc())
        .limit(10)
    )
    day = func.date(Assessment.completed_at)
    trend = db.execute(
        select(day, func.count())
        .where(
            *assessment_selection,
            Assessment.status == "completed",
            Assessment.completed_at >= now() - timedelta(days=30),
        )
        .group_by(day)
        .order_by(day)
    )
    trend_findings = dict(
        db.execute(
            select(day, func.count())
            .select_from(FindingObservation)
            .join(Assessment)
            .where(
                *assessment_selection,
                Assessment.status == "completed",
                Assessment.completed_at >= now() - timedelta(days=30),
                func.json_extract(FindingObservation.snapshot, "$.evaluation")
                == "finding",
            )
            .group_by(day)
        ).all()
    )
    return SecuritySummary(
        assessment_count=db.scalar(
            select(func.count()).select_from(Assessment).where(*assessment_selection)
        ),
        assets_with_open_findings=db.scalar(
            select(func.count(func.distinct(Finding.asset_id))).where(*active)
        ),
        open_counts=dict(
            db.execute(
                select(Finding.severity, func.count())
                .where(*active)
                .group_by(Finding.severity)
            ).all()
        ),
        recent=[assessment_view(row) for row in recent],
        trends=[
            {"day": label, "completed": count, "findings": trend_findings.get(label, 0)}
            for label, count in trend
        ],
    )
