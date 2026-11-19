from ipaddress import ip_address
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from app import scope as scope_module
from app.config import Settings
from app.main import create_app

BASE_URL = "http://127.0.0.1"
ASSET = {
    "ip_address": "127.0.0.1",
    "hostname": "lab.local",
    "display_name": "Lab service",
    "asset_type": "server",
    "description": "Local test endpoint",
    "operating_system": "Linux",
}


@pytest.fixture
def settings(tmp_path):
    return Settings(
        database_url=f"sqlite:///{(tmp_path / 'inventory.db').as_posix()}",
        approved_scope=["127.0.0.1", "::1"],
        discovery_limit=2,
    )


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings), base_url=BASE_URL) as client:
        yield client


@pytest.fixture
def probe(monkeypatch):
    probe = Mock(return_value="reachable")
    monkeypatch.setattr(
        scope_module,
        "probe_tcp_details",
        lambda address, port: (probe(address, port), None),
    )
    monkeypatch.setattr(scope_module, "sleep", Mock())
    return probe


def test_crud_and_restart(settings):
    with TestClient(create_app(settings), base_url=BASE_URL) as client:
        response = client.post("/api/assets", json=ASSET)
        assert response.status_code == 201
        asset = response.json()
        assert asset["status"] == "unknown"
        assert asset["first_seen"].endswith("Z")
        assert asset["last_checked"] is None
        path = f"/api/assets/{asset['id']}"

    with TestClient(create_app(settings), base_url=BASE_URL) as client:
        assert client.get("/api/assets").json() == [asset]
        assert client.get(path).json() == asset
        edited = client.put(
            path, json={**ASSET, "display_name": "Renamed", "ip_address": "::1"}
        )
        assert edited.status_code == 200
        assert edited.json()["display_name"] == "Renamed"
        assert edited.json()["ip_address"] == "::1"
        assert edited.json()["first_seen"] == asset["first_seen"]
        assert client.delete(path).status_code == 204
        assert client.get(path).status_code == 404
        assert client.get("/api/assets").json() == []


def test_duplicate_canonical_address_and_edit_conflict(client):
    first = client.post("/api/assets", json={**ASSET, "ip_address": "0:0:0:0:0:0:0:1"})
    assert first.status_code == 201
    assert first.json()["ip_address"] == "::1"
    assert (
        client.post("/api/assets", json={**ASSET, "ip_address": "::1"}).status_code
        == 409
    )
    second = client.post("/api/assets", json=ASSET).json()
    assert (
        client.put(
            f"/api/assets/{second['id']}", json={**ASSET, "ip_address": "::1"}
        ).status_code
        == 409
    )
    assert len(client.get("/api/assets").json()) == 2


@pytest.mark.parametrize(
    "invalid",
    [
        "127.1",
        "2130706433",
        "0177.0.0.1",
        "::ffff:127.0.0.1",
        "fe80::1%2",
        "http://127.0.0.1",
        "localhost",
        "127.0.0.1:8443",
    ],
)
def test_invalid_target_forms(client, invalid):
    assert (
        client.post("/api/assets", json={**ASSET, "ip_address": invalid}).status_code
        == 422
    )
    assert (
        client.post("/api/scope/validate", json={"ip_address": invalid}).status_code
        == 422
    )


def test_authorization_and_api_errors(client, probe):
    assert client.get("/api/scope").json()["networks"] == ["127.0.0.1/32", "::1/128"]
    for ip in ("192.168.10.2", "127.0.0.2", "8.8.8.8", "169.254.169.254"):
        assert (
            client.post("/api/scope/validate", json={"ip_address": ip}).status_code
            == 403
        )
        assert (
            client.post("/api/assets", json={**ASSET, "ip_address": ip}).status_code
            == 403
        )
    assert client.post("/api/scope/validate", json={"ip_address": "::1"}).json()[
        "approved"
    ]
    assert (
        client.get("/api/assets", headers={"host": "rebind.example"}).status_code == 400
    )
    assert client.get("/api/assets/0").status_code == 422
    assert client.get("/api/discovery-jobs/999").status_code == 404
    assert client.post("/api/assets/999/check", json={}).status_code == 404
    assert (
        client.post("/api/assets", json={**ASSET, "display_name": " "}).status_code
        == 422
    )
    assert (
        client.post("/api/assets", json={**ASSET, "hostname": "bad..host"}).status_code
        == 422
    )
    probe.assert_not_called()


@pytest.mark.parametrize("status", ["reachable", "unreachable", "unknown"])
def test_check_records_status_and_applies_rate_limit(client, probe, status):
    probe.return_value = status
    asset = client.post("/api/assets", json=ASSET).json()
    path = f"/api/assets/{asset['id']}"
    assert client.post(path + "/check").status_code == 422
    response = client.post(path + "/check", json={})
    assert response.status_code == 200
    assert response.json()["status"] == status
    assert response.json()["last_checked"].endswith("Z")
    assert client.get(path).json() == response.json()
    assert client.post(path + "/check", json={}).status_code == 429
    probe.assert_called_once_with(ip_address("127.0.0.1"), 8443)
    reset = client.put(path, json={**ASSET, "ip_address": "::1"}).json()
    assert reset["status"] == "unknown"
    assert reset["last_checked"] is None


def test_existing_asset_cannot_be_checked_after_scope_change(settings, probe):
    with TestClient(create_app(settings), base_url=BASE_URL) as client:
        asset = client.post("/api/assets", json=ASSET).json()
    restricted = settings.model_copy(update={"approved_scope": ["::1"]})
    with TestClient(create_app(restricted), base_url=BASE_URL) as client:
        path = f"/api/assets/{asset['id']}"
        assert client.get(path).status_code == 200
        assert client.post(path + "/check", json={}).status_code == 403
    probe.assert_not_called()


def test_configured_lab_cidr_allows_only_supported_targets(settings, probe):
    approved = settings.model_copy(
        update={"approved_scope": ["192.168.33.0/29"], "approved_service_port": 9443}
    )
    with TestClient(create_app(approved), base_url=BASE_URL) as client:
        asset = client.post(
            "/api/assets", json={**ASSET, "ip_address": "192.168.33.3"}
        ).json()
        assert (
            client.post(f"/api/assets/{asset['id']}/check", json={}).status_code == 200
        )
        for endpoint in ("192.168.33.0", "192.168.33.7", "192.168.33.8", "127.0.0.1"):
            assert (
                client.post(
                    "/api/scope/validate", json={"ip_address": endpoint}
                ).status_code
                == 403
            )
    probe.assert_called_once_with(ip_address("192.168.33.3"), 9443)
    public = settings.model_copy(update={"approved_scope": ["8.8.8.8"]})
    with pytest.raises(RuntimeError, match="Invalid approved laboratory scope"):
        with TestClient(create_app(public), base_url=BASE_URL):
            pass


def test_discovery_rejects_batch_before_probing(client, probe):
    path = "/api/discovery-jobs"
    assert (
        client.post(
            path, json={"targets": ["127.0.0.1"], "confirm_scope": False}
        ).status_code
        == 422
    )
    assert (
        client.post(
            path, json={"targets": ["127.0.0.1"], "confirm_scope": "true"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            path,
            json={"targets": ["127.0.0.1", "::1", "127.0.0.2"], "confirm_scope": True},
        ).status_code
        == 422
    )
    assert (
        client.post(
            path, json={"targets": ["127.0.0.1", "127.0.0.2"], "confirm_scope": True}
        ).status_code
        == 403
    )
    assert (
        client.post(
            path, json={"targets": ["::1", "0:0:0:0:0:0:0:1"], "confirm_scope": True}
        ).status_code
        == 422
    )
    assert client.get(path).json() == []
    probe.assert_not_called()


def test_discovery_persists_only_confirmed_assets_and_results(client, probe):
    probe.side_effect = ["reachable", "unreachable"]
    path = "/api/discovery-jobs"
    response = client.post(
        path, json={"targets": ["127.0.0.1", "::1"], "confirm_scope": True}
    )
    assert response.status_code == 201
    job = response.json()
    assert [item["status"] for item in job["results"]] == ["reachable", "unreachable"]
    assert client.get(f"{path}/{job['id']}").json() == job
    assert client.get(path).json() == [job]
    (asset,) = client.get("/api/assets").json()
    assert asset["display_name"] == asset["ip_address"] == "127.0.0.1"
    assert asset["hostname"] is None and asset["operating_system"] is None
    assert asset["last_checked"] == job["results"][0]["checked_at"]
    assert probe.call_count == 2


def test_concurrent_operation_rejected(client, probe):
    asset = client.post("/api/assets", json=ASSET).json()
    with client.app.state.scope.operation():
        assert (
            client.post(f"/api/assets/{asset['id']}/check", json={}).status_code == 429
        )
    probe.assert_not_called()
