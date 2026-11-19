from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect

from app.config import Settings
from app.main import API_VERSION, create_app


def test_health_initializes_sqlite(tmp_path):
    database_path = tmp_path / "test.db"
    settings = Settings(database_url=f"sqlite:///{database_path.as_posix()}")

    with TestClient(create_app(settings), base_url="http://127.0.0.1") as client:
        response = client.get("/api/health")
        contract = client.get("/openapi.json").json()
        missing = client.get("/api/nonexistent")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-LuniScan-API-Version"] == API_VERSION == contract["info"]["version"]
    assert {"get", "post"} <= contract["paths"]["/api/assets"].keys()
    assert missing.status_code == 404
    engine = create_engine(settings.database_url)
    try:
        assert inspect(engine).has_table("app_metadata")
    finally:
        engine.dispose()


def test_health_reports_unavailable_database(tmp_path):
    settings = Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    app = create_app(settings)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        with app.state.engine.begin() as connection:
            connection.exec_driver_sql("DROP TABLE app_metadata")
        response = client.get("/api/health")

    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "database": "unavailable"}
