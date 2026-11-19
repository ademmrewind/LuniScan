import csv
from datetime import UTC, date
from io import StringIO
from typing import Annotated, Literal
from unicodedata import category, normalize

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError

from app.analytics import Period
from app.inventory import DB, ApprovedScope, AssetID, find_asset
from app.scan_models import (
    ComparisonView,
    Confirmation,
    HistoryView,
    JobDetail,
    JobInput,
    JobSummary,
    JobView,
    PlannedCheck,
    ResultView,
    ScanJob,
    ScanResult,
    Service,
    ServiceInput,
    ServiceView,
    now,
    utc,
)
from app.scan_runner import ApprovalChanged, logger, run_job, verify_approval
from app.scope import Availability

router = APIRouter(prefix="/api", tags=["service monitoring"])


def approved(value: bool) -> None:
    if not value:
        raise HTTPException(422, "Explicit approval is required.")


def find_job(db: DB, job_id: int) -> ScanJob:
    job = db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(404, "Scan job not found.")
    return job


def result_view(result: ScanResult) -> ResultView:
    return ResultView.model_validate(result).model_copy(
        update={"checked_at": utc(result.checked_at)}
    )


def job_results(db: DB, job_id: int) -> list[ResultView]:
    rows = db.scalars(
        select(ScanResult).where(ScanResult.job_id == job_id).order_by(ScanResult.id)
    )
    return [result_view(row) for row in rows]


def job_view(job: ScanJob, rows: list[ResultView]) -> JobView:
    return JobView(
        id=job.id,
        status=job.status,
        created_at=job.created_at.replace(tzinfo=UTC),
        started_at=utc(job.started_at),
        completed_at=utc(job.completed_at),
        asset_count=job.asset_count,
        check_count=job.check_count,
        done_count=len(rows),
        progress=100 * len(rows) // job.check_count,
        failure=job.failure,
        summary=JobSummary(
            reachable=sum(row.status == "reachable" for row in rows),
            unreachable=sum(row.status == "unreachable" for row in rows),
            unknown=sum(row.status == "unknown" for row in rows),
        ),
    )


@router.get("/services")
def list_services(db: DB) -> list[ServiceView]:
    return [
        ServiceView.model_validate(service)
        for service in db.scalars(select(Service).order_by(Service.name, Service.id))
    ]


@router.post("/services", status_code=201)
def create_service(payload: ServiceInput, db: DB) -> ServiceView:
    approved(payload.confirm_approval)
    service = db.scalar(select(Service).where(Service.port == payload.port))
    if service is not None:
        if service.active or service.name != payload.name:
            raise HTTPException(
                409, "Port already registered. Reapprove it with its original name."
            )
        service.active = True
    else:
        service = Service(name=payload.name, port=payload.port)
        db.add(service)
    try:
        db.commit()
    except IntegrityError:
        raise HTTPException(409, "Port already registered.") from None
    logger.info("Service %d approved", service.id)
    return ServiceView.model_validate(service)


@router.delete("/services/{service_id}", status_code=204)
def revoke_service(service_id: AssetID, db: DB) -> None:
    service = db.get(Service, service_id)
    if service is None:
        raise HTTPException(404, "Service not found.")
    db.execute(
        update(Service)
        .where(Service.id == service_id, Service.active.is_(True))
        .values(active=False, approval_revision=Service.approval_revision + 1)
    )
    db.commit()
    logger.info("Service %d approval revoked", service_id)


@router.post("/scan-jobs", status_code=201)
def create_job(payload: JobInput, db: DB, scope: ApprovedScope) -> JobView:
    approved(payload.confirm_approval)
    if len(set(payload.asset_ids)) != len(payload.asset_ids) or len(
        set(payload.service_ids)
    ) != len(payload.service_ids):
        raise HTTPException(422, "Select each asset and service only once.")
    if len(payload.asset_ids) * len(payload.service_ids) > 12:
        raise HTTPException(422, "A job may contain at most 12 service checks.")
    assets = [find_asset(db, asset_id) for asset_id in payload.asset_ids]
    for asset in assets:
        scope.require(asset.ip_address)
    services = [db.get(Service, service_id) for service_id in payload.service_ids]
    if any(service is None or not service.active for service in services):
        raise HTTPException(422, "Select services with active approval.")
    plan = [
        PlannedCheck(
            asset_id=asset.id,
            asset_name=asset.display_name,
            ip_address=asset.ip_address,
            address_revision=asset.address_revision,
            service_id=service.id,
            service_revision=service.approval_revision,
            service_name=service.name,
            port=service.port,
        ).model_dump()
        for asset in assets
        for service in services
        if service is not None
    ]
    job = ScanJob(
        created_at=now(),
        status="pending",
        asset_count=len(assets),
        check_count=len(plan),
        plan=plan,
    )
    db.add(job)
    db.commit()
    logger.info("Scan job %d created with %d approved checks", job.id, job.check_count)
    return job_view(job, [])


@router.get("/scan-jobs")
def list_jobs(db: DB) -> list[JobView]:
    jobs = list(db.scalars(select(ScanJob).order_by(ScanJob.id.desc()).limit(50)))
    return [job_view(job, job_results(db, job.id)) for job in jobs]


@router.get("/scan-jobs/{job_id}")
def read_job(job_id: AssetID, db: DB) -> JobDetail:
    job = find_job(db, job_id)
    results = job_results(db, job_id)
    return JobDetail(
        **job_view(job, results).model_dump(), plan=job.plan, results=results
    )


@router.post("/scan-jobs/{job_id}/start", status_code=202)
def start_job(
    job_id: AssetID,
    payload: Confirmation,
    tasks: BackgroundTasks,
    db: DB,
    scope: ApprovedScope,
) -> JobView:
    approved(payload.confirm_approval)
    job = find_job(db, job_id)
    if job.status != "pending":
        raise HTTPException(409, "Only pending jobs can be started.")
    plan = [PlannedCheck.model_validate(check) for check in job.plan]
    try:
        for check in plan:
            verify_approval(db, check, scope)
    except ApprovalChanged:
        raise HTTPException(
            409, "An asset or service approval changed. Create a new job."
        ) from None
    try:
        changed = db.execute(
            update(ScanJob)
            .where(ScanJob.id == job_id, ScanJob.status == "pending")
            .values(status="running", started_at=now())
        ).rowcount
        if not changed:
            raise HTTPException(409, "Job status changed.")
        db.commit()
    except IntegrityError:
        raise HTTPException(409, "Another scan job is already running.") from None
    logger.info("Scan job %d started", job_id)
    response = job_view(job, [])
    tasks.add_task(run_job, db.get_bind(), scope, job_id, plan)
    return response


@router.post("/scan-jobs/{job_id}/cancel")
def cancel_job(job_id: AssetID, payload: Confirmation, db: DB) -> JobView:
    approved(payload.confirm_approval)
    job = find_job(db, job_id)
    changed = db.execute(
        update(ScanJob)
        .where(ScanJob.id == job_id, ScanJob.status.in_(("pending", "running")))
        .values(status="cancelled", completed_at=now())
    ).rowcount
    if not changed and job.status != "cancelled":
        raise HTTPException(409, "Only pending or running jobs can be cancelled.")
    db.commit()
    logger.info("Scan job %d cancelled", job_id)
    return job_view(job, job_results(db, job_id))


@router.get("/scan-history")
def history(
    db: DB,
    q: Annotated[str, Query(max_length=100)] = "",
    status: Availability | None = None,
    asset_id: AssetID | None = None,
    service_id: AssetID | None = None,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    start: date | None = None,
    end: date | None = None,
) -> list[HistoryView]:
    statement = (
        select(ScanResult, ScanJob).join(ScanJob).where(ScanJob.status == "completed")
    )
    if q.strip():
        statement = statement.where(
            or_(
                *(
                    column.icontains(q.strip(), autoescape=True)
                    for column in (
                        ScanResult.asset_name,
                        ScanResult.service_name,
                        ScanResult.ip_address,
                    )
                )
            )
        )
    if status is not None:
        statement = statement.where(ScanResult.status == status)
    if asset_id is not None:
        statement = statement.where(ScanResult.asset_id == asset_id)
    if service_id is not None:
        statement = statement.where(ScanResult.service_id == service_id)
    if start is not None or end is not None:
        period = Period(start or date.min, end or date.max)
        if period.start > period.end:
            raise HTTPException(422, "Choose an ordered UTC date range.")
        statement = statement.where(period.includes(ScanResult.checked_at))
    return [
        HistoryView(
            **result_view(result).model_dump(),
            duration_seconds=(job.completed_at - job.started_at).total_seconds(),
        )
        for result, job in db.execute(
            statement.order_by(ScanResult.id.desc()).offset(offset).limit(50)
        )
    ]


@router.get("/scan-history/{result_id}/comparison")
def compare(result_id: AssetID, db: DB) -> ComparisonView:
    row = db.scalar(
        select(ScanResult)
        .join(ScanJob)
        .where(ScanResult.id == result_id, ScanJob.status == "completed")
    )
    if row is None:
        raise HTTPException(404, "Completed result not found.")
    prior = db.scalar(
        select(ScanResult)
        .join(ScanJob)
        .where(
            ScanJob.status == "completed",
            ScanResult.id < row.id,
            ScanResult.asset_id == row.asset_id,
            ScanResult.service_id == row.service_id,
            ScanResult.address_revision == row.address_revision,
        )
        .order_by(ScanResult.id.desc())
        .limit(1)
    )
    change = "inconclusive"
    if prior is not None and "unknown" not in (prior.status, row.status):
        if row.status == prior.status:
            change = "unchanged"
        else:
            change = (
                "newly_reachable" if row.status == "reachable" else "became_unreachable"
            )
    return ComparisonView(
        result=result_view(row),
        previous=result_view(prior) if prior else None,
        change=change,
    )


def csv_cell(value: str) -> str:
    candidate = normalize("NFKC", value)
    for char in candidate:
        if char in "\t\r\n":
            return "'" + value
        if not char.isspace() and category(char) not in {"Cc", "Cf"}:
            if char in "=+-@":
                return "'" + value
            break
    return value


@router.get(
    "/scan-jobs/{job_id}/export/{format}",
    response_model=list[ResultView],
    responses={200: {"content": {"text/csv": {"schema": {"type": "string"}}}}},
)
def export(job_id: AssetID, format: Literal["json", "csv"], db: DB) -> Response:
    if find_job(db, job_id).status != "completed":
        raise HTTPException(409, "Export is available for completed jobs.")
    results = job_results(db, job_id)
    data = [row.model_dump(mode="json") for row in results]
    headers = {
        "Content-Disposition": f'attachment; filename="scan-{job_id}.{format}"',
        "Cache-Control": "no-store",
    }
    if format == "json":
        return JSONResponse(data, headers=headers)
    output = StringIO(newline="")
    fields = list(ResultView.model_fields)
    writer = csv.DictWriter(output, fieldnames=fields, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    for row in data:
        writer.writerow(
            {
                key: csv_cell(value) if isinstance(value, str) else value
                for key, value in row.items()
            }
        )
    return Response(output.getvalue(), media_type="text/csv", headers=headers)
