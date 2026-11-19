import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from io import BytesIO
from threading import Event

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from app import assessments
from app.assessment_rules import header_rules, tls_rules
from app.config import Settings
from app.main import create_app
from app.monitor_engine import Certificate, Outcome, ResponseEvidence

ROOT = "/api/security"
BASE = "http://127.0.0.1"


@pytest.fixture
def settings(tmp_path):
    return Settings(
        database_url=f"sqlite:///{(tmp_path / 'security-assessment.db').as_posix()}"
    )


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings), base_url=BASE) as client:
        yield client


def profile(client, protocol="http"):
    asset = client.post(
        "/api/assets",
        json={
            "ip_address": "127.0.0.1",
            "display_name": "=Example",
            "asset_type": "server",
        },
    ).json()
    response = client.post(
        "/api/monitoring/profiles",
        json={
            "asset_id": asset["id"],
            "ip_address": asset["ip_address"],
            "name": "Lab endpoint",
            "protocol": protocol,
            "port": 8443,
            "confirm_approval": True,
            "path": "/health" if protocol in {"http", "https"} else "/",
        },
    )
    assert response.status_code == 201
    return response.json()


def payload(item, **fields):
    return {
        "asset_id": item["asset_id"],
        "profile_id": item["id"],
        "confirm_authorization": True,
        **fields,
    }


def response(status=200, certificate=None):
    return Outcome(
        health="healthy",
        duration_ms=1.1,
        outcome="connected",
        http_status=status,
        certificate=certificate,
    )


def by_rule(items):
    return {item.rule: item for item in items}


def test_header_values_context_and_sanitization():
    evidence = ResponseEvidence()
    evidence.capture(
        [
            (
                b"content-security-policy",
                b"script-src 'nonce-private-nonce' 'unsafe-inline'; frame-ancestors 'none'",
            ),
            (b"strict-transport-security", b"max-age=0"),
            (b"x-content-type-options", b"nosniff"),
            (b"referrer-policy", b"no-referrer, unsafe-url"),
            (b"permissions-policy", b"camera=*"),
            (b"set-cookie", b"private-cookie"),
        ]
    )
    plain = by_rule(header_rules("http", response(), evidence))
    assert plain["strict-transport-security"].evaluation == "not_applicable"
    assert plain["strict-transport-security"].present
    assert (
        plain["x-frame-options"].evaluation == "pass"
        and not plain["x-frame-options"].present
    )
    assert plain["content-security-policy"].evaluation == "pass"
    assert plain["x-content-type-options"].evaluation == "pass"
    assert (
        plain["referrer-policy"].severity
        == plain["permissions-policy"].severity
        == "low"
    )
    assert "set-cookie" not in evidence.headers
    assert all("private-" not in item.model_dump_json() for item in plain.values())
    https = by_rule(header_rules("https", response(), evidence))
    assert https["strict-transport-security"].evaluation == "finding"
    assert https["strict-transport-security"].evidence == "max-age=0"
    incomplete = by_rule(header_rules("https", response(302), evidence))
    assert all(item.evaluation == "inconclusive" for item in incomplete.values())


@pytest.mark.parametrize(
    ("policies", "expected"),
    [
        (["script-src 'unsafe-eval'"], "finding"),
        (["default-src 'none'"], "pass"),
        (["frame-ancestors 'none'"], "finding"),
        (["script-src *", "script-src 'none'"], "inconclusive"),
    ],
)
def test_csp_rule(policies, expected):
    rows = by_rule(
        header_rules(
            "https",
            response(),
            ResponseEvidence(headers={"content-security-policy": policies}),
        )
    )
    assert rows["content-security-policy"].evaluation == expected


def test_tls_uses_only_available_evidence():
    failed = Certificate(
        state="hostname_mismatch",
        verified=False,
        hostname_valid=False,
        inspected_at=datetime.now(UTC),
    )
    rows = by_rule(tls_rules("https", response(None, failed), ResponseEvidence()))
    assert rows["tls_verification"].severity == "medium"
    assert (
        rows["tls_expiration"].evaluation
        == rows["tls_protocol"].evaluation
        == "inconclusive"
    )
    valid = Certificate(
        state="valid",
        verified=True,
        hostname_valid=True,
        days_remaining=60,
        inspected_at=datetime.now(UTC),
    )
    rows = by_rule(
        tls_rules(
            "https",
            response(200, valid),
            ResponseEvidence(
                tls_version="TLSv1.3", tls_cipher="TLS_AES_128_GCM_SHA256"
            ),
        )
    )
    assert all(item.evaluation == "pass" for item in rows.values())
    assert all(
        item.evaluation == "not_applicable"
        for item in tls_rules("http", response(), ResponseEvidence())
    )


def test_authorization_and_scope_rejection(client, monkeypatch):
    item = profile(client)
    seen = []

    async def probe(*args):
        seen.append(args)
        return response()

    monkeypatch.setattr(assessments, "observe", probe)
    assert (
        client.post(
            ROOT + "/assessments", json=payload(item, confirm_authorization=False)
        ).status_code
        == 422
    )
    assert (
        client.post(
            ROOT + "/assessments", json=payload(item, asset_id=item["asset_id"] + 1)
        ).status_code
        == 409
    )
    client.app.state.scope.networks = ()
    assert client.post(ROOT + "/assessments", json=payload(item)).status_code == 403
    assert client.get(ROOT + "/assessments").json() == []
    assert not seen


def test_profile_must_be_enabled_http(client):
    item = profile(client, "tcp")
    assert client.post(ROOT + "/assessments", json=payload(item)).status_code == 422


def run(client, item):
    client.app.state.scope._next_probe = 0
    created = client.post(ROOT + "/assessments", json=payload(item))
    assert created.status_code == 202
    assert created.json()["authorized"]
    return client.get(ROOT + "/assessments/" + str(created.json()["id"])).json()


def test_finding_lifecycle_exports_and_persistence(settings, monkeypatch):
    cases = iter(
        [
            (200, []),
            (200, []),
            (503, [(b"x-content-type-options", b"nosniff")]),
            (200, [(b"x-content-type-options", b"nosniff")]),
        ]
    )

    async def probe(address, target, days, evidence):
        status, headers = next(cases)
        assert str(address) == "127.0.0.1"
        assert (
            target.port == 8443
            and target.path == "/health"
            and target.expected_content is None
        )
        evidence.capture(headers + [(b"set-cookie", b"private-cookie")])
        return response(status)

    monkeypatch.setattr(assessments, "observe", probe)
    with TestClient(create_app(settings), base_url=BASE) as client:
        item = profile(client)
        first = run(client, item)
        assert (
            first["status"] == "completed" and first["summary"]["not_applicable"] == 4
        )
        assert first["summary"]["counts"] == {"low": 1, "informational": 4}
        finding = next(
            row
            for row in client.get(ROOT + "/findings").json()
            if row["rule"] == "x-content-type-options"
        )
        uri = ROOT + f"/findings/{finding['id']}"
        second = run(client, item)
        assert len(client.get(ROOT + "/findings").json()) == 5
        assert (
            client.post(uri + "/acknowledge", json={}).json()["status"]
            == "acknowledged"
        )
        incomplete = run(client, item)
        assert incomplete["summary"]["inconclusive"] == 5
        assert client.get(uri).json()["status"] == "acknowledged"
        final = run(client, item)
        details = client.get(uri).json()
        assert details["status"] == "resolved" and details["resolved_at"]
        assert len(details["history"]) == 4
        assert details["last_observed"] == second["completed_at"]
        assert client.get(ROOT + "/summary").json()["trends"][-1]["findings"] == 14
        export = ROOT + f"/assessments/{final['id']}/export/"
        assert "private-cookie" not in client.get(export + "json").text
        assert "'=Example" in client.get(export + "csv").text
        pdf = client.get(export + "pdf")
        assert pdf.status_code == 200
        text = " ".join(
            page.extract_text() for page in PdfReader(BytesIO(pdf.content)).pages
        )
        assert "Security Assessment" in text and "Coverage and severity" in text
    with TestClient(create_app(settings), base_url=BASE) as client:
        assert (
            client.get(ROOT + "/assessments?limit=2&offset=1").json()[0]["id"]
            == incomplete["id"]
        )
        assert client.get(uri).json()["status"] == "resolved"
        assert client.get("/api/assets").json()[0]["display_name"] == "=Example"


def test_cancel_discards_inflight_observations(client, monkeypatch):
    entered, release = Event(), Event()

    async def probe(*_):
        entered.set()
        assert await asyncio.to_thread(release.wait, 5)
        return response()

    monkeypatch.setattr(assessments, "observe", probe)
    item = profile(client)
    with ThreadPoolExecutor(max_workers=1) as pool:
        ongoing = pool.submit(client.post, ROOT + "/assessments", json=payload(item))
        try:
            assert entered.wait(5)
            (current,) = client.get(ROOT + "/assessments").json()
            uri = ROOT + f"/assessments/{current['id']}"
            assert client.post(uri + "/cancel", json={}).json()["status"] == "cancelled"
        finally:
            release.set()
        assert ongoing.result(5).status_code == 202
    assert client.get(uri).json()["observations"] == []
    assert client.get(ROOT + "/findings").json() == []
