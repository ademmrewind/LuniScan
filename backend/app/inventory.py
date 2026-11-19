from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StringConstraints,
    field_validator,
)
from sqlalchemy import (
    JSON,
    DateTime,
    Integer,
    String,
    exists,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from app.audit import asset_events
from app.database import metadata
from app.scope import Availability, ProbeError, Scope, parse_address

router = APIRouter(prefix="/api", tags=["inventory"])


class Base(DeclarativeBase):
    metadata = metadata


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True)
    hostname: Mapped[str | None] = mapped_column(String(253))
    display_name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(String(1000))
    asset_type: Mapped[str] = mapped_column(String(50))
    operating_system: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(12), default="unknown")
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_checked: Mapped[datetime | None] = mapped_column(DateTime)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    group_name: Mapped[str | None] = mapped_column(String(60))
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(String(2000), default="")
    address_revision: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = {"sqlite_autoincrement": True}


class DiscoveryJob(Base):
    __tablename__ = "discovery_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime)
    results: Mapped[list[dict]] = mapped_column(JSON)


class AssetObservation(Base):
    __tablename__ = "asset_observations"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(index=True)
    ip_address: Mapped[str] = mapped_column(String(45))
    status: Mapped[str] = mapped_column(String(12))
    checked_at: Mapped[datetime] = mapped_column(DateTime)
    duration_ms: Mapped[float | None]
    port: Mapped[int]
    error_category: Mapped[str | None] = mapped_column(String(24))


IPLiteral = Annotated[str, StringConstraints(min_length=2, max_length=45)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=100)]
Label = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=60)
]


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AssetInput(InputModel):
    ip_address: IPLiteral
    hostname: (
        Annotated[
            str,
            StringConstraints(
                max_length=253,
                pattern=r"^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$",
            ),
        ]
        | None
    ) = None
    display_name: ShortText
    description: str = Field(default="", max_length=1000)
    asset_type: str = Field(min_length=1, max_length=50)
    operating_system: ShortText | None = None
    group_name: Label | None = None
    tags: list[Label] = Field(default_factory=list, max_length=20)
    notes: str = Field(default="", max_length=2000)

    @field_validator("tags")
    @classmethod
    def unique_tags(cls, values: list[str]) -> list[str]:
        unique = {}
        for value in values:
            unique.setdefault(value.casefold(), value)
        return list(unique.values())

    @field_validator("ip_address")
    @classmethod
    def canonical_ip(cls, value: str) -> str:
        return str(parse_address(value))


class AssetView(AssetInput):
    model_config = ConfigDict(from_attributes=True)
    id: int
    status: Availability
    first_seen: datetime
    last_checked: datetime | None
    last_seen: datetime | None

    @field_validator("first_seen", "last_checked", "last_seen")
    @classmethod
    def utc_timestamp(cls, value: datetime | None) -> datetime | None:
        return value.replace(tzinfo=UTC) if value is not None else None


class ScopeTarget(InputModel):
    ip_address: IPLiteral


class ScopeView(BaseModel):
    networks: list[str]
    service_port: int
    discovery_limit: int


class ScopeValidation(BaseModel):
    ip_address: str
    approved: bool


class CheckRequest(InputModel):
    pass


class DiscoveryRequest(InputModel):
    targets: list[IPLiteral] = Field(min_length=1, max_length=8)
    confirm_scope: StrictBool


class DiscoveryResult(BaseModel):
    ip_address: str
    status: Availability
    checked_at: datetime
    port: int | None = None
    duration_ms: float | None = None
    error_category: ProbeError | None = None


class DiscoveryView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    completed_at: datetime
    results: list[DiscoveryResult]

    @field_validator("completed_at")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        return value.replace(tzinfo=UTC)


def session(request: Request):
    with Session(request.app.state.engine) as db:
        yield db


def get_scope(request: Request) -> Scope:
    return request.app.state.scope


DB = Annotated[Session, Depends(session)]
ApprovedScope = Annotated[Scope, Depends(get_scope)]
AssetID = Annotated[int, Field(gt=0, le=2**63 - 1)]


def find_asset(db: Session, asset_id: int) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found.")
    return asset


def save_asset(db: Session, new_asset: Asset | None = None) -> None:
    try:
        if new_asset is not None:
            db.flush()
            record_asset_event(
                db, "asset_created", new_asset.id, new_asset.display_name
            )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            409, "An asset with this IP address already exists."
        ) from None


def record_asset_event(db: Session, kind: str, asset_id: int, name: str) -> None:
    db.execute(
        asset_events.insert().values(
            kind=kind, asset_id=asset_id, asset_name=name, occurred_at=datetime.now(UTC)
        )
    )


@router.get("/assets")
def list_assets(
    db: DB,
    q: Annotated[str, Query(max_length=100)] = "",
    group: Annotated[str | None, Query(max_length=60)] = None,
    tag: Annotated[str | None, Query(max_length=60)] = None,
    asset_type: Annotated[str | None, Query(max_length=50)] = None,
    status: Availability | None = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int | None, Query(ge=1, le=200)] = None,
) -> list[AssetView]:
    """List inventory records, with optional exact filters and pagination."""
    statement = select(Asset).order_by(Asset.display_name, Asset.id).offset(offset)
    if limit is not None:
        statement = statement.limit(limit)
    if q.strip():
        statement = statement.where(
            or_(
                *(
                    column.icontains(q.strip(), autoescape=True)
                    for column in (
                        Asset.ip_address,
                        Asset.display_name,
                        Asset.hostname,
                        Asset.description,
                        Asset.notes,
                    )
                )
            )
        )
    for column, value in (
        (Asset.group_name, group),
        (Asset.asset_type, asset_type),
        (Asset.status, status),
    ):
        if value is not None:
            statement = statement.where(func.lower(column) == value.strip().lower())
    if tag is not None:
        entries = func.json_each(Asset.tags).table_valued("value")
        statement = statement.where(
            exists(
                select(1)
                .select_from(entries)
                .where(func.lower(entries.c.value) == tag.strip().lower())
            )
        )
    return [AssetView.model_validate(asset) for asset in db.scalars(statement)]


@router.post("/assets", status_code=201)
def add_asset(payload: AssetInput, db: DB, scope: ApprovedScope) -> AssetView:
    scope.require(payload.ip_address)
    asset = Asset(**payload.model_dump(), first_seen=datetime.now(UTC))
    db.add(asset)
    save_asset(db, asset)
    return AssetView.model_validate(asset)


@router.get("/assets/{asset_id}")
def get_asset(asset_id: AssetID, db: DB) -> AssetView:
    return AssetView.model_validate(find_asset(db, asset_id))


@router.put("/assets/{asset_id}")
def edit_asset(
    asset_id: AssetID, payload: AssetInput, db: DB, scope: ApprovedScope
) -> AssetView:
    asset = find_asset(db, asset_id)
    if asset.ip_address != payload.ip_address:
        scope.require(payload.ip_address)
        asset.address_revision = Asset.address_revision + 1
        asset.status = "unknown"
        asset.last_checked = None
        asset.last_seen = None
    values = payload.model_dump()
    for field in ("group_name", "notes", "tags"):
        if field not in payload.model_fields_set:
            values.pop(field)
    for field, value in values.items():
        setattr(asset, field, value)
    save_asset(db)
    return AssetView.model_validate(asset)


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: AssetID, db: DB) -> None:
    asset = find_asset(db, asset_id)
    record_asset_event(db, "asset_deleted", asset.id, asset.display_name)
    db.delete(asset)
    db.commit()


@router.get("/scope")
def read_scope(scope: ApprovedScope) -> ScopeView:
    return ScopeView(
        networks=[str(network) for network in scope.networks],
        service_port=scope.port,
        discovery_limit=scope.discovery_limit,
    )


@router.post("/scope/validate")
def validate_scope(payload: ScopeTarget, scope: ApprovedScope) -> ScopeValidation:
    return ScopeValidation(
        ip_address=str(scope.require(payload.ip_address)), approved=True
    )


@router.post("/assets/{asset_id}/check")
def check_asset(
    asset_id: AssetID, payload: CheckRequest, db: DB, scope: ApprovedScope
) -> AssetView:
    asset = find_asset(db, asset_id)
    address, revision = asset.ip_address, asset.address_revision
    scope.require(address)
    db.rollback()
    with scope.operation():
        result = measured_result(scope, address)
        values = {"status": result.status, "last_checked": result.checked_at}
        if result.status == "reachable":
            values["last_seen"] = result.checked_at
        changed = db.execute(
            update(Asset)
            .where(Asset.id == asset_id, Asset.address_revision == revision)
            .values(**values)
        )
        if changed.rowcount != 1:
            raise HTTPException(
                409, "Asset changed during the check. Refresh and try again."
            )
        record_observation(db, asset_id, result)
        db.commit()
        return AssetView.model_validate(find_asset(db, asset_id))


def approved_targets(payload: DiscoveryRequest, scope: Scope) -> list[str]:
    if not payload.confirm_scope:
        raise HTTPException(422, "Confirm authorization for every target.")
    if len(payload.targets) > scope.discovery_limit:
        raise HTTPException(422, "Discovery target limit exceeded.")
    targets = [str(scope.require(target)) for target in payload.targets]
    if len(set(targets)) != len(targets):
        raise HTTPException(422, "Discovery targets must be unique.")
    return targets


def measured_result(scope: Scope, address: str, before=None) -> DiscoveryResult:
    status, category, duration = scope.probe_service(address, scope.port, before)
    return DiscoveryResult(
        ip_address=address,
        status=status,
        error_category=category,
        duration_ms=duration,
        port=scope.port,
        checked_at=datetime.now(UTC),
    )


def record_observation(db: Session, asset_id: int, result: DiscoveryResult) -> None:
    db.add(AssetObservation(asset_id=asset_id, **result.model_dump()))


def save_discovery_result(db: Session, result: DiscoveryResult) -> None:
    if result.status == "reachable":
        asset_id = db.scalar(
            insert(Asset)
            .values(
                ip_address=result.ip_address,
                display_name=result.ip_address,
                description="",
                asset_type="unknown",
                first_seen=result.checked_at,
                last_checked=result.checked_at,
                last_seen=result.checked_at,
                status=result.status,
            )
            .on_conflict_do_nothing(index_elements=[Asset.ip_address])
            .returning(Asset.id)
        )
        if asset_id is not None:
            record_asset_event(db, "asset_created", asset_id, result.ip_address)
            record_observation(db, asset_id, result)
            return
    values = {"status": result.status, "last_checked": result.checked_at}
    if result.status == "reachable":
        values["last_seen"] = result.checked_at
    asset_id = db.scalar(
        update(Asset)
        .where(Asset.ip_address == result.ip_address)
        .values(**values)
        .returning(Asset.id)
    )
    if asset_id is not None:
        record_observation(db, asset_id, result)


@router.post("/discovery-jobs", status_code=201)
def discover(payload: DiscoveryRequest, db: DB, scope: ApprovedScope) -> DiscoveryView:
    targets = approved_targets(payload, scope)
    with scope.operation():
        results = [measured_result(scope, target) for target in targets]
        for result in results:
            save_discovery_result(db, result)
        job = DiscoveryJob(
            completed_at=datetime.now(UTC),
            results=[result.model_dump(mode="json") for result in results],
        )
        db.add(job)
        db.commit()
        return DiscoveryView.model_validate(job)


@router.get("/discovery-jobs")
def list_jobs(db: DB) -> list[DiscoveryView]:
    jobs = db.scalars(select(DiscoveryJob).order_by(DiscoveryJob.id.desc()).limit(50))
    return [DiscoveryView.model_validate(job) for job in jobs]


@router.get("/discovery-jobs/{job_id}")
def get_job(job_id: AssetID, db: DB) -> DiscoveryView:
    job = db.get(DiscoveryJob, job_id)
    if job is None:
        raise HTTPException(404, "Discovery job not found.")
    return DiscoveryView.model_validate(job)
