from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address
from sqlite3 import connect
from threading import Event
from unittest.mock import MagicMock, Mock

import pytest
from fastapi.testclient import TestClient

from app import scope
from app.config import Settings
from app.main import create_app

BASE = "http://127.0.0.1"
ASSET = {
    "ip_address": "127.0.0.1",
    "display_name": "Local endpoint",
    "asset_type": "server",
}


def configured(path):
    return Settings(database_url=f"sqlite:///{path.as_posix()}", discovery_limit=2)


@pytest.fixture
def client(tmp_path):
    with TestClient(
        create_app(configured(tmp_path / "inventory.db")), base_url=BASE
    ) as browser:
        yield browser


def test_groups_tags_filters_and_legacy_edit(client):
    payload = {
        **ASSET,
        "ip_address": "0:0:0:0:0:0:0:1",
        "group_name": "Engineering",
        "tags": [" Blue ", "internal", "blue"],
        "notes": "Quarterly review",
    }
    response = client.post("/api/assets", json=payload)
    assert response.status_code == 201
    asset = response.json()
    assert asset["ip_address"] == "::1"
    assert asset["tags"] == ["Blue", "internal"]
    assert asset["last_seen"] is None
    client.post("/api/assets", json=ASSET)
    filtered = client.get(
        "/api/assets",
        params={
            "group": "engineering",
            "tag": "BLUE",
            "asset_type": "server",
            "q": "quarterly",
            "status": "unknown",
            "limit": 1,
        },
    ).json()
    assert filtered == [asset]
    assert client.get("/api/assets?tag=other").json() == []
    assert client.get("/api/assets?limit=1&offset=2").json() == []
    updated = client.put(
        f"/api/assets/{asset['id']}",
        json={
            **ASSET,
            "ip_address": "::1",
            "display_name": "Renamed",
        },
    ).json()
    assert updated["group_name"] == "Engineering" and updated["tags"] == asset["tags"]
    assert updated["notes"] == "Quarterly review"


def test_migration_is_additive_and_repeatable(tmp_path):
    path = tmp_path / "legacy.db"
    settings = configured(path)
    with TestClient(create_app(settings), base_url=BASE) as client:
        asset = client.post("/api/assets", json=ASSET).json()
    with connect(path) as db:
        db.execute("DROP INDEX phase6_asset_group")
        for column in ("notes", "tags", "group_name", "last_seen"):
            db.execute(f"ALTER TABLE assets DROP COLUMN {column}")
        db.execute("ALTER TABLE scan_results DROP COLUMN duration_ms")
    for _ in range(2):
        with TestClient(create_app(settings), base_url=BASE) as client:
            migrated = client.get(f"/api/assets/{asset['id']}").json()
            assert migrated == asset
            assert client.get("/api/scan-history").json() == []


def test_discovery_validates_entire_explicit_approved_list(client, monkeypatch):
    probe = Mock(return_value=("reachable", None))
    monkeypatch.setattr(scope, "probe_tcp_details", probe)
    route = "/api/discovery-runs"
    assert (
        client.post(
            route, json={"targets": ["127.0.0.1"], "confirm_scope": False}
        ).status_code
        == 422
    )
    assert (
        client.post(
            route,
            json={"targets": ["127.0.0.1", "192.168.99.8"], "confirm_scope": True},
        ).status_code
        == 403
    )
    assert (
        client.post(
            route, json={"targets": ["::1", "0:0:0:0:0:0:0:1"], "confirm_scope": True}
        ).status_code
        == 422
    )
    assert client.get(route).json() == []
    probe.assert_not_called()


def test_cancellation_discards_in_flight_result_and_skips_pending(client, monkeypatch):
    entered, release = Event(), Event()

    def connect_once(*_):
        entered.set()
        assert release.wait(5)
        return "reachable", None

    probe = Mock(side_effect=connect_once)
    monkeypatch.setattr(scope, "probe_tcp_details", probe)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(
            client.post,
            "/api/discovery-runs",
            json={
                "targets": ["127.0.0.1", "::1"],
                "confirm_scope": True,
            },
        )
        try:
            assert entered.wait(5)
            (run,) = client.get("/api/discovery-runs").json()
            assert run["status"] == "running"
            route = f"/api/discovery-runs/{run['id']}"
            assert (
                client.post(route + "/cancel", json={}).json()["status"] == "cancelled"
            )
        finally:
            release.set()
        assert pending.result(5).status_code == 202
    assert client.get(route).json()["results"] == []
    assert client.get("/api/assets").json() == []
    probe.assert_called_once_with(ip_address("127.0.0.1"), 8443)


def test_discovery_observations_and_named_service_duration(client, monkeypatch):
    probe = Mock(side_effect=[("reachable", None), ("unreachable", "refused")])
    monkeypatch.setattr(scope, "probe_tcp_details", probe)
    monkeypatch.setattr(scope, "sleep", Mock())
    response = client.post(
        "/api/discovery-runs", json={"targets": ["127.0.0.1"], "confirm_scope": True}
    )
    assert response.status_code == 202
    run = client.get(f"/api/discovery-runs/{response.json()['id']}").json()
    assert run["status"] == "completed"
    assert run["results"][0]["duration_ms"] >= 0
    (asset,) = client.get("/api/assets").json()
    assert asset["last_seen"] == run["results"][0]["checked_at"]
    service = client.post(
        "/api/services",
        json={
            "name": "Lab service",
            "port": 9000,
            "confirm_approval": True,
        },
    ).json()
    job = client.post(
        "/api/scan-jobs",
        json={
            "asset_ids": [asset["id"]],
            "service_ids": [service["id"]],
            "confirm_approval": True,
        },
    ).json()
    assert (
        client.post(
            f"/api/scan-jobs/{job['id']}/start", json={"confirm_approval": True}
        ).status_code
        == 202
    )
    details = client.get(f"/api/assets/{asset['id']}/intelligence").json()
    (result,) = details["latest_results"]
    assert result["error_category"] == "refused" and result["duration_ms"] >= 0
    assert result["service_name"] == service["name"] and result["port"] == 9000
    assert details["last_connectivity_check"] == result["checked_at"]
    assert details["monitored_services"] == [service]
    assert len(details["service_history"]) == len(details["availability_history"]) == 1


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (None, ("reachable", None)),
        (TimeoutError(), ("unreachable", "timeout")),
        (ConnectionRefusedError(), ("unreachable", "refused")),
        (OSError(), ("unknown", "socket_error")),
    ],
)
def test_tcp_outcome_classification(monkeypatch, error, expected):
    socket = MagicMock()
    socket.return_value.__enter__.return_value.connect.side_effect = error
    monkeypatch.setattr(scope.socket, "socket", socket)
    assert scope.probe_tcp_details(ip_address("::1"), 8443) == expected
