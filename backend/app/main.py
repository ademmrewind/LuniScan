import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, event
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.analytics import analytics_indexes
from app.analytics import router as analytics_router
from app.config import Settings
from app.database import check_database, initialize_database
from app.inventory import router as inventory_router
from app.reporting import router as reporting_router
from app.scan_runner import recover_jobs
from app.scans import router as scans_router
from app.scope import Scope
from app.security import LocalAPIProtection

logger = logging.getLogger(__name__)
API_VERSION = "0.4.1"


class HealthStatus(BaseModel):
    status: Literal["ok", "degraded"]
    database: Literal["ok", "unavailable"]


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        config = settings if settings is not None else Settings()
        try:
            application.state.scope = Scope(
                config.approved_scope, config.approved_service_port, config.discovery_limit
            )
        except ValueError:
            raise RuntimeError("Invalid approved laboratory scope configuration.") from None
        engine = create_engine(config.database_url, hide_parameters=True)

        @event.listens_for(engine, "connect")
        def configure_sqlite(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")

        try:
            try:
                initialize_database(engine)
                for index in analytics_indexes:
                    index.create(engine, checkfirst=True)
                recover_jobs(engine)
            except SQLAlchemyError:
                raise RuntimeError("Could not initialize the SQLite database.") from None
            application.state.engine = engine
            yield
        finally:
            engine.dispose()

    application = FastAPI(title="LuniScan API", version=API_VERSION, lifespan=lifespan)
    application.add_middleware(LocalAPIProtection)
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])
    application.include_router(inventory_router)
    application.include_router(scans_router)
    application.include_router(analytics_router)
    application.include_router(reporting_router)

    @application.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, error: RequestValidationError) -> JSONResponse:
        details = [{key: issue[key] for key in ("loc", "msg", "type")} for issue in error.errors()]
        return JSONResponse({"detail": details}, status_code=422)

    @application.exception_handler(SQLAlchemyError)
    async def database_error(_request: Request, _error: SQLAlchemyError) -> JSONResponse:
        logger.error("Database operation failed")
        return JSONResponse({"detail": "Database operation failed."}, status_code=503)

    @application.get("/api/health", responses={503: {"model": HealthStatus}})
    def health(request: Request, response: Response) -> HealthStatus:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-LuniScan-API-Version"] = API_VERSION
        try:
            check_database(request.app.state.engine)
        except SQLAlchemyError:
            logger.warning("SQLite health check failed")
            response.status_code = 503
            return HealthStatus(status="degraded", database="unavailable")
        return HealthStatus(status="ok", database="ok")

    return application


app = create_app()
