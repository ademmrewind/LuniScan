import logging

from fastapi import HTTPException
from sqlalchemy import update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.inventory import Asset
from app.scan_models import PlannedCheck, ScanJob, ScanResult, Service, now
from app.scope import Scope

logger = logging.getLogger("uvicorn.error.luniscan.scans")


class JobStopped(Exception):
    pass


class ApprovalChanged(Exception):
    pass


def verify_approval(db: Session, check: PlannedCheck, scope: Scope) -> None:
    scope.require(check.ip_address)
    asset = db.get(Asset, check.asset_id)
    service = db.get(Service, check.service_id)
    if (
        asset is None
        or asset.ip_address != check.ip_address
        or asset.address_revision != check.address_revision
        or service is None
        or not service.active
        or service.port != check.port
        or service.approval_revision != check.service_revision
    ):
        raise ApprovalChanged


def finish(
    engine: Engine, job_id: int, status: str, failure: str | None = None
) -> None:
    with Session(engine) as db:
        changed = db.execute(
            update(ScanJob)
            .where(ScanJob.id == job_id, ScanJob.status == "running")
            .values(status=status, completed_at=now(), failure=failure)
        ).rowcount
        db.commit()
    if changed:
        logger.info("Scan job %d transitioned to %s", job_id, status)


def recover_jobs(engine: Engine) -> None:
    with Session(engine) as db:
        changed = db.execute(
            update(ScanJob)
            .where(ScanJob.status == "running")
            .values(status="failed", completed_at=now(), failure="interrupted")
        ).rowcount
        db.commit()
    if changed:
        logger.warning("%d interrupted scan jobs marked failed", changed)


def run_job(
    engine: Engine, scope: Scope, job_id: int, plan: list[PlannedCheck]
) -> None:
    def before(check: PlannedCheck) -> None:
        with Session(engine) as db:
            job = db.get(ScanJob, job_id)
            if job is None or job.status != "running":
                raise JobStopped
            verify_approval(db, check, scope)

    try:
        with scope.operation(wait_for_cooldown=True):
            for check in plan:
                try:
                    status, category = scope.probe_service(
                        check.ip_address, check.port, lambda: before(check)
                    )
                except ApprovalChanged:
                    status, category = "unknown", "approval_changed"
                except HTTPException as error:
                    if error.status_code not in (403, 422):
                        raise
                    status, category = "unknown", "scope_denied"

                with Session(engine) as db:
                    changed = db.execute(
                        update(ScanJob)
                        .where(ScanJob.id == job_id, ScanJob.status == "running")
                        .values(done_count=ScanJob.done_count + 1)
                    ).rowcount
                    if not changed:
                        return
                    db.add(
                        ScanResult(
                            job_id=job_id,
                            **check.model_dump(exclude={"service_revision"}),
                            status=status,
                            error_category=category,
                            checked_at=now(),
                        )
                    )
                    db.commit()
    except JobStopped:
        return
    except HTTPException:
        finish(engine, job_id, "failed", "network_busy")
    except Exception:
        logger.error("Scan job %d encountered an internal error", job_id)
        finish(engine, job_id, "failed", "internal_error")
    else:
        finish(engine, job_id, "completed")
