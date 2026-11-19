import csv
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from threading import Event
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update
from sqlalchemy.orm import Session

from app import scope
from app.config import Settings
from app.main import create_app
from app.scan_models import ScanJob

URL = "http://127.0.0.1"
CONFIRM = {"confirm_approval": True}


@pytest.fixture
def settings(tmp_path):
    return Settings(
        database_url=f"sqlite:///{(tmp_path / 'scans.db').as_posix()}",
        approved_scope=["127.0.0.1", "::1"],
    )


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings), base_url=URL) as client:
        yield client


@pytest.fixture
def probe(monkeypatch):
    probe = Mock(return_value=("reachable", None))
    monkeypatch.setattr(scope, "probe_tcp_details", probe)
    monkeypatch.setattr(scope, "sleep", Mock())
    return probe


def add_asset(client, ip="127.0.0.1", name="Lab node"):
    response = client.post(
        "/api/assets",
        json={"ip_address": ip, "display_name": name, "asset_type": "server"},
    )
    assert response.status_code == 201
    return response.json()["id"]


def add_service(client, port=9443, name="Lab service"):
    response = client.post(
        "/api/services", json={"port": port, "name": name, **CONFIRM}
    )
    assert response.status_code == 201
    return response.json()["id"]


def create_job(client, asset_id, service_ids):
    response = client.post(
        "/api/scan-jobs",
        json={
            "asset_ids": [asset_id],
            "service_ids": service_ids,
            **CONFIRM,
        },
    )
    assert response.status_code == 201
    assert response.json()["status"] == "pending"
    return "/api/scan-jobs/" + str(response.json()["id"])


def run(client, path):
    assert client.post(path + "/start", json=CONFIRM).status_code == 202
    job = client.get(path).json()
    assert job["status"] == "completed"
    return job


@pytest.mark.parametrize("port", [0, 65536, "443", 443.5, True])
def test_invalid_ports(client, port):
    assert (
        client.post(
            "/api/services", json={"name": "Test", "port": port, **CONFIRM}
        ).status_code
        == 422
    )


def test_configuration_and_approval(client, probe):
    assert (
        client.post(
            "/api/services",
            json={"name": "Test", "port": 8443, "confirm_approval": False},
        ).status_code
        == 422
    )
    service_id = add_service(client)
    assert client.get("/api/services").json() == [
        {"id": service_id, "name": "Lab service", "port": 9443, "active": True}
    ]
    assert (
        client.post(
            "/api/services", json={"name": "Duplicate", "port": 9443, **CONFIRM}
        ).status_code
        == 409
    )
    asset_id = add_asset(client)
    path = create_job(client, asset_id, [service_id])
    assert client.delete(f"/api/services/{service_id}").status_code == 204
    assert client.post(path + "/start", json=CONFIRM).status_code == 409
    assert (
        client.post(
            "/api/scan-jobs",
            json={
                "asset_ids": [asset_id],
                "service_ids": [service_id],
                **CONFIRM,
            },
        ).status_code
        == 422
    )
    probe.assert_not_called()
    assert add_service(client) == service_id
    assert client.post(path + "/start", json=CONFIRM).status_code == 409


def test_job_lifecycle_and_history(client, probe):
    asset_id = add_asset(client)
    service_id = add_service(client)
    path = create_job(client, asset_id, [service_id])
    assert client.get(path).json()["progress"] == 0
    assert client.get(path + "/export/json").status_code == 409
    assert (
        client.post(path + "/start", json={"confirm_approval": False}).status_code
        == 422
    )
    job = run(client, path)
    assert (
        job["progress"] == 100 and job["asset_count"] == 1 and job["check_count"] == 1
    )
    assert job["summary"] == {"reachable": 1, "unreachable": 0, "unknown": 0}
    assert job["created_at"] < job["started_at"] < job["completed_at"]
    (result,) = job["results"]
    assert result["checked_at"].endswith("Z")
    assert result["error_category"] is None
    assert client.get("/api/scan-history", params={"status": "unknown"}).json() == []
    assert client.get("/api/scan-history", params={"q": "%"}).json() == []
    (row,) = client.get(
        "/api/scan-history",
        params={
            "q": "lAB",
            "status": "reachable",
            "asset_id": asset_id,
            "service_id": service_id,
        },
    ).json()
    assert row["id"] == result["id"] and row["duration_seconds"] >= 0
    assert client.post(path + "/start", json=CONFIRM).status_code == 409
    assert client.post(path + "/cancel", json=CONFIRM).status_code == 409
    assert probe.call_count == 1
    assert probe.call_args.args[1] == 9443


def test_running_cancellation_stops_pending_checks(client, probe):
    path = create_job(
        client, add_asset(client), [add_service(client), add_service(client, 8443)]
    )
    other = create_job(client, add_asset(client, "::1"), [add_service(client, 7443)])
    entered, release = Event(), Event()

    def blocked(*args):
        entered.set()
        assert release.wait(5)
        return "reachable", None

    probe.side_effect = blocked
    with ThreadPoolExecutor(max_workers=1) as pool:
        response = pool.submit(client.post, path + "/start", json=CONFIRM)
        try:
            assert entered.wait(5)
            assert client.get(path).json()["status"] == "running"
            assert client.post(other + "/start", json=CONFIRM).status_code == 409
            assert (
                client.post(path + "/cancel", json=CONFIRM).json()["status"]
                == "cancelled"
            )
        finally:
            release.set()
        assert response.result(timeout=5).status_code == 202
    job = client.get(path).json()
    assert (
        job["status"] == "cancelled" and job["done_count"] == 0 and job["results"] == []
    )
    assert job["completed_at"]
    assert probe.call_count == 1


def test_pending_cancel_and_interrupted_recovery(settings, probe):
    with TestClient(create_app(settings), base_url=URL) as client:
        asset_id, service_id = add_asset(client), add_service(client)
        cancelled = create_job(client, asset_id, [service_id])
        assert (
            client.post(cancelled + "/cancel", json=CONFIRM).json()["status"]
            == "cancelled"
        )
        assert client.post(cancelled + "/start", json=CONFIRM).status_code == 409
        interrupted = create_job(client, asset_id, [service_id])
        job_id = int(interrupted.rsplit("/", 1)[1])
        with Session(client.app.state.engine) as db:
            db.execute(
                update(ScanJob).where(ScanJob.id == job_id).values(status="running")
            )
            db.commit()
    with TestClient(create_app(settings), base_url=URL) as client:
        recovered = client.get(interrupted).json()
        assert recovered["status"] == "failed" and recovered["failure"] == "interrupted"
    probe.assert_not_called()


def test_scope_is_required_at_creation_and_start(settings, probe):
    with TestClient(create_app(settings), base_url=URL) as client:
        asset_id = add_asset(client, "::1")
        service_id = add_service(client)
        path = create_job(client, asset_id, [service_id])
    restricted = settings.model_copy(update={"approved_scope": ["127.0.0.1"]})
    with TestClient(create_app(restricted), base_url=URL) as client:
        assert client.post(path + "/start", json=CONFIRM).status_code == 403
        assert (
            client.post(
                "/api/scan-jobs",
                json={
                    "asset_ids": [asset_id],
                    "service_ids": [service_id],
                    **CONFIRM,
                },
            ).status_code
            == 403
        )
    probe.assert_not_called()


def test_revalidates_service_before_each_connection(client, probe):
    first, second = add_service(client), add_service(client, 8444)
    path = create_job(client, add_asset(client), [first, second])

    def change_approval(*args):
        assert client.delete(f"/api/services/{second}").status_code == 204
        return "reachable", None

    probe.side_effect = change_approval
    job = run(client, path)
    assert job["results"][1]["error_category"] == "approval_changed"
    assert job["results"][1]["status"] == "unknown"
    assert probe.call_count == 1


def test_comparison_persistence_and_exports(settings, probe):
    probe.side_effect = [
        ("unreachable", "refused"),
        ("reachable", None),
        ("reachable", None),
        ("unreachable", "timeout"),
        ("unknown", "socket_error"),
    ]
    with TestClient(create_app(settings), base_url=URL) as client:
        asset_id = add_asset(client, name="=1+1")
        service_id = add_service(client, name="@formula")
        for expected in [
            "inconclusive",
            "newly_reachable",
            "unchanged",
            "became_unreachable",
            "inconclusive",
        ]:
            path = create_job(client, asset_id, [service_id])
            job = run(client, path)
            result_id = job["results"][0]["id"]
            comparison = client.get(f"/api/scan-history/{result_id}/comparison").json()
            assert comparison["change"] == expected
    with TestClient(create_app(settings), base_url=URL) as client:
        assert len(client.get("/api/scan-history").json()) == 5
        assert client.get(path).json() == job
        exported = client.get(path + "/export/json")
        assert exported.json() == job["results"]
        assert "attachment" in exported.headers["content-disposition"]
        csv_response = client.get(path + "/export/csv")
        (row,) = list(csv.DictReader(StringIO(csv_response.text)))
        assert row["asset_name"] == "'=1+1" and row["service_name"] == "'@formula"
        assert row["port"] == "9443" and row["job_id"] == str(job["id"])
        assert row["error_category"] == "socket_error" and row["checked_at"].endswith(
            "Z"
        )
        assert client.get(path + "/export/xml").status_code == 422
