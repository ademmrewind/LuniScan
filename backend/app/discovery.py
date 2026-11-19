from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import JSON, DateTime, Index, String, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.inventory import (
    DB,
    ApprovedScope,
    AssetID,
    Base,
    CheckRequest,
    DiscoveryRequest,
    DiscoveryResult,
    approved_targets,
    measured_result,
    save_discovery_result,
)
from app.scan_models import now, utc
from app.scan_runner import JobStopped, logger
from app.scope import Scope

router = APIRouter(prefix="/api/discovery-runs", tags=["discovery"])


class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(12))
    failure: Mapped[str | None] = mapped_column(String(30))
    targets: Mapped[list[str]] = mapped_column(JSON)
    results: Mapped[list[dict]] = mapped_column(JSON, default=list)
    port: Mapped[int]


Index(
    "one_running_discovery",
    DiscoveryRun.status,
    unique=True,
    sqlite_where=DiscoveryRun.status == "running",
)


class DiscoveryRunView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    completed_at: datetime | None
    status: Literal["running", "completed", "cancelled", "failed"]
    failure: str | None
    targets: list[str]
    results: list[DiscoveryResult]
    port: int

    @field_validator("created_at", "completed_at")
    @classmethod
    def timestamps(cls, value: datetime | None) -> datetime | None:
        return utc(value)


def settle(
    engine: Engine, run_id: int, status: str, failure: str | None = None
) -> None:
    with Session(engine) as db, db.begin():
        db.execute(
            update(DiscoveryRun)
            .where(DiscoveryRun.id == run_id, DiscoveryRun.status == "running")
            .values(status=status, failure=failure, completed_at=now())
        )
    logger.info("Discovery run %s worker stopped", run_id)


def recover_discovery(engine: Engine) -> None:
    with Session(engine) as db, db.begin():
        db.execute(
            update(DiscoveryRun)
            .where(DiscoveryRun.status == "running")
            .values(status="failed", failure="interrupted", completed_at=now())
        )


def execute_discovery(
    engine: Engine, scope: Scope, run_id: int, targets: list[str]
) -> None:
    def before() -> None:
        with Session(engine) as db:
            status = db.scalar(
                select(DiscoveryRun.status).where(DiscoveryRun.id == run_id)
            )
            if status != "running":
                raise JobStopped

    try:
        with scope.operation(wait_for_cooldown=True):
            recorded = []
            for target in targets:
                result = measured_result(scope, target, before)
                recorded.append(result.model_dump(mode="json"))
                with Session(engine) as db, db.begin():
                    changed = db.execute(
                        update(DiscoveryRun)
                        .where(
                            DiscoveryRun.id == run_id, DiscoveryRun.status == "running"
                        )
                        .values(results=recorded)
                    )
                    if changed.rowcount != 1:
                        return
                    save_discovery_result(db, result)
    except JobStopped:
        return
    except HTTPException as error:
        settle(
            engine,
            run_id,
            "failed",
            "network_busy" if error.status_code == 429 else "scope_denied",
        )
    except Exception:
        logger.error("Discovery run %s encountered an internal error", run_id)
        settle(engine, run_id, "failed", "internal_error")
    else:
        settle(engine, run_id, "completed")


def find_run(db: DB, run_id: int) -> DiscoveryRun:
    run = db.get(DiscoveryRun, run_id)
    if run is None:
        raise HTTPException(404, "Discovery run not found.")
    return run


@router.post("", status_code=202)
def start(
    payload: DiscoveryRequest, tasks: BackgroundTasks, db: DB, scope: ApprovedScope
) -> DiscoveryRunView:
    """Start a user-approved list of literal IPs on the configured discovery port."""
    targets = approved_targets(payload, scope)
    run = DiscoveryRun(
        created_at=now(), status="running", targets=targets, port=scope.port
    )
    db.add(run)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(429, "A discovery run is already active.") from None
    response = DiscoveryRunView.model_validate(run)
    logger.info("Discovery run %s started", run.id)
    tasks.add_task(execute_discovery, db.get_bind(), scope, run.id, targets)
    return response


@router.get("")
def list_runs(
    db: DB,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> list[DiscoveryRunView]:
    return [
        DiscoveryRunView.model_validate(run)
        for run in db.scalars(
            select(DiscoveryRun)
            .order_by(DiscoveryRun.id.desc())
            .offset(offset)
            .limit(limit)
        )
    ]


@router.get("/{run_id}")
def read(run_id: AssetID, db: DB) -> DiscoveryRunView:
    return DiscoveryRunView.model_validate(find_run(db, run_id))


@router.post("/{run_id}/cancel")
def cancel(run_id: AssetID, payload: CheckRequest, db: DB) -> DiscoveryRunView:
    """Stop pending targets and preserve only results committed before cancellation."""
    find_run(db, run_id)
    changed = db.execute(
        update(DiscoveryRun)
        .where(DiscoveryRun.id == run_id, DiscoveryRun.status == "running")
        .values(status="cancelled", completed_at=now())
    )
    db.commit()
    run = find_run(db, run_id)
    if not changed.rowcount and run.status != "cancelled":
        raise HTTPException(409, "Discovery run already finished.")
    logger.info("Discovery run %s cancelled", run_id)
    return DiscoveryRunView.model_validate(run)
