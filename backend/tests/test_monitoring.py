import asyncio
import socket
import ssl
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

from app import monitor_engine, monitoring
from app.config import Settings
from app.main import create_app
from app.monitor_engine import (
    Certificate,
    CheckTarget,
    Outcome,
    certificate_info,
    observe,
)

BASE = "http://127.0.0.1"
ROOT = "/api/monitoring"
TARGET = CheckTarget("http", 8443, "lab.test", 500, "/health", 200, 299, "ready")


def config(tmp_path):
    return Settings(database_url=f"sqlite:///{(tmp_path / 'monitor.db').as_posix()}")


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(config(tmp_path)), base_url=BASE) as client:
        yield client


def profile_payload(client):
    asset = client.post(
        "/api/assets",
        json={
            "ip_address": "127.0.0.1",
            "display_name": "Lab node",
            "asset_type": "server",
        },
    ).json()
    return {
        "asset_id": asset["id"],
        "ip_address": asset["ip_address"],
        "name": "Health endpoint",
        "protocol": "http",
        "port": 8443,
        "expected_content": "private-marker",
        "confirm_approval": True,
    }


def create_profile(client):
    response = client.post(ROOT + "/profiles", json=profile_payload(client))
    assert response.status_code == 201
    profile = response.json()
    assert profile["checks_content"] and "private-marker" not in response.text
    return profile


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"ip_address": "192.168.10.10"}, 403),
        ({"ip_address": "::1"}, 409),
        ({"confirm_approval": False}, 422),
        ({"hostname": "https://lab.test"}, 422),
        ({"path": "//other"}, 422),
        ({"path": "/x/../other"}, 422),
        ({"port": 65536}, 422),
        ({"timeout_ms": 10000}, 422),
        ({"status_min": 300, "status_max": 200}, 422),
    ],
)
def test_profile_validation(client, changes, code):
    assert (
        client.post(
            ROOT + "/profiles", json={**profile_payload(client), **changes}
        ).status_code
        == code
    )


def test_revoked_asset_address_disables_checks(client, monkeypatch):
    profile = create_profile(client)
    fake = AsyncMock()
    monkeypatch.setattr(monitoring, "observe", fake)
    assert (
        client.put(
            f"/api/assets/{profile['asset_id']}",
            json={
                "ip_address": "::1",
                "display_name": "Lab node",
                "asset_type": "server",
            },
        ).status_code
        == 200
    )
    assert (
        client.post(ROOT + f"/profiles/{profile['id']}/check", json={}).status_code
        == 409
    )
    fake.assert_not_awaited()


def test_rate_limit_and_scope_guard(client, monkeypatch):
    profile = create_profile(client)
    fake = AsyncMock()
    monkeypatch.setattr(monitoring, "observe", fake)
    scope = client.app.state.scope
    with scope.operation():
        assert (
            client.post(ROOT + f"/profiles/{profile['id']}/check", json={}).status_code
            == 429
        )
    scope.networks = ()
    assert (
        client.post(ROOT + f"/profiles/{profile['id']}/check", json={}).status_code
        == 403
    )
    fake.assert_not_awaited()


def test_alerts_acknowledge_deduplicate_resolve_and_persist(tmp_path, monkeypatch):
    from io import BytesIO

    from pypdf import PdfReader

    healthy = Outcome(
        health="healthy",
        duration_ms=2.5,
        outcome="connected",
        http_status=200,
        expected_status=True,
    )
    degraded = Outcome(
        health="degraded",
        duration_ms=4.5,
        outcome="connected",
        http_status=503,
        expected_status=False,
    )
    down = Outcome(
        health="unreachable", duration_ms=4.2, outcome="refused", error="refused"
    )
    fake = AsyncMock(side_effect=[healthy, down, degraded, degraded, degraded, healthy])
    monkeypatch.setattr(monitoring, "observe", fake)
    settings = config(tmp_path)
    with TestClient(create_app(settings), base_url=BASE) as client:
        profile = create_profile(client)
        base = ROOT + f"/profiles/{profile['id']}"
        for expected in (healthy, down, degraded, degraded, degraded):
            client.app.state.scope._next_probe = 0
            result = client.post(base + "/check", json={})
            assert result.status_code == 201
            assert result.json()["duration_ms"] == expected.duration_ms
        alerts = client.get(ROOT + "/alerts?status=active").json()
        assert sorted(row["kind"] for row in alerts) == [
            "became_unreachable",
            "health_degraded",
            "repeated_failures",
        ]
        alert = alerts[0]
        acknowledged = client.post(
            ROOT + f"/alerts/{alert['id']}/acknowledge", json={}
        ).json()
        assert (
            acknowledged["status"] == "acknowledged" and acknowledged["acknowledged_at"]
        )
        client.app.state.scope._next_probe = 0
        assert client.post(base + "/check", json={}).status_code == 201
        assert client.get(ROOT + "/alerts?status=active").json() == []
        report = client.get("/api/reports/pdf?kind=monitoring")
        pdf = " ".join(
            " ".join(page.extract_text().split())
            for page in PdfReader(BytesIO(report.content)).pages
        )
        assert "Service health summary" in pdf
        assert "Health endpoint" in pdf
        assert "private-marker" not in pdf
    with TestClient(create_app(settings), base_url=BASE) as client:
        detail = client.get(base).json()
        assert len(detail["history"]) == 6
        assert len(client.get(ROOT + "/alerts?status=resolved").json()) == 3
        assert detail["profile"]["last_success"] and detail["profile"]["last_failure"]
        assert client.get(ROOT + "/summary").json()["profiles"] == {"healthy": 1}
        assert client.delete(base).status_code == 204
        assert client.get(ROOT + "/profiles").json() == []


@pytest.mark.parametrize(
    ("wire", "health", "error"),
    [
        (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nready", "healthy", None),
        (
            b"HTTP/1.1 503 Error\r\nContent-Length: 5\r\n\r\nready",
            "degraded",
            "unexpected_status",
        ),
        (
            b"HTTP/1.1 302 Found\r\nLocation: http://external.invalid/\r\nContent-Length: 0\r\n\r\n",
            "degraded",
            "redirect_blocked",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 9000\r\n\r\n" + b"x" * 9000,
            "degraded",
            "content_inconclusive",
        ),
    ],
)
def test_http_bounded_engine_and_numeric_destination(monkeypatch, wire, health, error):
    writer = Mock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    reader = Mock()
    reader.read = AsyncMock(
        side_effect=[wire[n : n + 2048] for n in range(0, len(wire), 2048)] + [b""]
    )
    dial = AsyncMock(return_value=(reader, writer))
    monkeypatch.setattr(monitor_engine.asyncio, "open_connection", dial)
    result = asyncio.run(observe(ip_address("127.0.0.1"), TARGET, 30))
    assert result.health == health and result.error == error and result.duration_ms >= 0
    dial.assert_awaited_once()
    assert dial.call_args.args == ("127.0.0.1", 8443)
    assert dial.call_args.kwargs["flags"] == socket.AI_NUMERICHOST
    assert b"Host: lab.test:8443" in writer.write.call_args_list[0].args[0]


def test_timeout(monkeypatch):
    bad = AsyncMock(side_effect=TimeoutError)
    monkeypatch.setattr(monitor_engine.asyncio, "open_connection", bad)
    outcome = asyncio.run(observe(ip_address("::1"), TARGET, 30))
    assert outcome.health == "unreachable" and outcome.outcome == "timeout"


@pytest.mark.parametrize(
    ("code", "state"), [(18, "untrusted"), (62, "hostname_mismatch"), (10, "expired")]
)
def test_tls_verification_has_no_insecure_retry(monkeypatch, code, state):
    error = ssl.SSLCertVerificationError()
    error.verify_code = code
    dial = AsyncMock(side_effect=error)
    monkeypatch.setattr(monitor_engine.asyncio, "open_connection", dial)
    target = CheckTarget("tls", 8443, "lab.test", 500, "/", 200, 299, None)
    result = asyncio.run(observe(ip_address("127.0.0.1"), target, 30))
    assert result.certificate.state == state and not result.certificate.verified
    assert result.certificate.subject is None and result.certificate.expires_at is None
    dial.assert_awaited_once()
    context = dial.call_args.kwargs["ssl"]
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert dial.call_args.kwargs["server_hostname"] == "lab.test"


def test_certificate_dates():
    checked = datetime(2026, 1, 1, tzinfo=UTC)
    certificate = certificate_info(
        {
            "notBefore": "Dec  1 00:00:00 2025 GMT",
            "notAfter": "Jan 10 00:00:00 2026 GMT",
            "subject": ((("commonName", "lab.test"),),),
        },
        checked,
        30,
    )
    assert certificate.state == "expiring_soon" and certificate.days_remaining == 9
    assert certificate.expires_at == datetime(2026, 1, 10, tzinfo=UTC)
    assert certificate.subject == "commonName=lab.test"


def test_certificate_alert_recovery_requires_verified_observation(client, monkeypatch):
    checked = datetime.now(UTC)
    expiring = Certificate(
        state="expiring_soon",
        expires_at=checked + timedelta(days=7),
        days_remaining=7,
        verified=True,
        hostname_valid=True,
        inspected_at=checked,
    )
    untrusted = Certificate(state="untrusted", verified=False, inspected_at=checked)
    valid = Certificate(
        state="valid",
        expires_at=checked + timedelta(days=60),
        days_remaining=60,
        verified=True,
        hostname_valid=True,
        inspected_at=checked,
    )
    monkeypatch.setattr(
        monitoring,
        "observe",
        AsyncMock(
            side_effect=[
                Outcome(
                    health="healthy",
                    duration_ms=2,
                    outcome="connected",
                    certificate=expiring,
                ),
                Outcome(
                    health="degraded",
                    duration_ms=2,
                    outcome="tls_failed",
                    certificate=untrusted,
                ),
                Outcome(health="unreachable", duration_ms=10, outcome="timeout"),
                Outcome(
                    health="healthy",
                    duration_ms=2,
                    outcome="connected",
                    certificate=valid,
                ),
            ]
        ),
    )
    profile = client.post(
        ROOT + "/profiles",
        json={
            **profile_payload(client),
            "protocol": "tls",
            "expected_content": None,
        },
    ).json()
    check = ROOT + f"/profiles/{profile['id']}/check"
    for _ in range(3):
        client.app.state.scope._next_probe = 0
        assert client.post(check, json={}).status_code == 201
    opened = {
        alert["kind"]: alert
        for alert in client.get(ROOT + "/alerts?status=active").json()
    }
    assert opened["certificate_expiring"]["severity"] == "critical"
    assert "certificate_verification" in opened
    client.app.state.scope._next_probe = 0
    assert client.post(check, json={}).status_code == 201
    resolved = {
        alert["kind"] for alert in client.get(ROOT + "/alerts?status=resolved").json()
    }
    assert {"certificate_expiring", "certificate_verification"} <= resolved


def test_https_keeps_verification_and_returns_certificate(monkeypatch):
    writer = Mock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    writer.get_extra_info.return_value.getpeercert.return_value = {
        "notBefore": "Jan  1 00:00:00 2020 GMT",
        "notAfter": "Jan  1 00:00:00 2099 GMT",
    }
    reader = Mock()
    reader.read = AsyncMock(
        return_value=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )
    dial = AsyncMock(return_value=(reader, writer))
    monkeypatch.setattr(monitor_engine.asyncio, "open_connection", dial)
    target = CheckTarget("https", 8443, "lab.test", 500, "/", 200, 299, None)
    check = asyncio.run(observe(ip_address("127.0.0.1"), target, 30))
    assert check.health == "healthy" and check.http_status == 200
    assert check.certificate.state == "valid" and check.certificate.verified
    assert dial.call_args.kwargs["ssl"].verify_mode == ssl.CERT_REQUIRED
