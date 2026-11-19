from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from app import scope
from app.config import Settings
from app.main import create_app
from app.scans import csv_cell
from app.security import MAX_BODY_BYTES

BASE = "http://127.0.0.1"
ASSET = {"ip_address": "127.0.0.1", "display_name": "Lab asset", "asset_type": "server"}


@pytest.fixture
def client(tmp_path):
    settings = Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    with TestClient(create_app(settings), base_url=BASE) as client:
        yield client


def test_origin_and_asset_workflow(client):
    route = "/api/assets"
    rejected = client.post(
        route, json=ASSET, headers={"Origin": "https://example.test"}
    )
    assert rejected.status_code == 403
    assert client.get(route).json() == []
    result = client.post(route, json=ASSET, headers={"Origin": BASE})
    assert result.status_code == 201
    target = f"{route}/{result.json()['id']}"
    assert client.delete(target, headers={"Origin": "null"}).status_code == 403
    assert client.get(target).json()["display_name"] == ASSET["display_name"]
    preflight = client.options(
        route,
        headers={
            "Origin": "https://example.test",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert preflight.status_code == 405
    assert "access-control-allow-origin" not in preflight.headers


def test_body_limits_and_content_type(client):
    route = "/api/assets"
    assert client.post(route, content=b"x" * (MAX_BODY_BYTES + 1)).status_code == 413
    assert (
        client.post(
            route,
            content=iter([b"x" * MAX_BODY_BYTES, b"x"]),
            headers={"Content-Type": "application/json"},
        ).status_code
        == 413
    )
    assert (
        client.post(
            route, content="{}", headers={"Content-Type": "text/plain"}
        ).status_code
        == 415
    )
    assert client.get(route).json() == []


def test_validation_does_not_echo_payload(client):
    value = "private-value-that-should-not-be-echoed"
    result = client.post("/api/assets", json={**ASSET, "asset_type": [value]})
    assert result.status_code == 422
    assert value not in result.text
    assert result.json()["detail"][0]["loc"][-1] == "asset_type"


def test_denied_cross_origin_discovery_does_not_connect(client, monkeypatch):
    probe = Mock()
    monkeypatch.setattr(scope, "tcp_probe", probe)
    result = client.post(
        "/api/discovery-jobs",
        json={
            "targets": ["127.0.0.1"],
            "confirm_scope": True,
        },
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert result.status_code == 403
    probe.assert_not_called()


@pytest.mark.parametrize("value", ["\u200b=2", " \tdata", "＝2", "\ufeff @command"])
def test_csv_neutralizes_formula_prefixes(value):
    assert csv_cell(value) == "'" + value
