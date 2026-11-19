from datetime import UTC, datetime
from io import BytesIO
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader
from sqlalchemy import insert, update
from sqlalchemy.orm import Session

from app import scope
from app.config import Settings
from app.inventory import Asset
from app.main import create_app
from app.scan_models import ScanJob, ScanResult

PERIOD = {"start": "2025-04-02", "end": "2025-04-03"}
CONFIRM = {"confirm_approval": True}


@pytest.fixture
def client(tmp_path):
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'reporting.db').as_posix()}",
        approved_scope=["127.0.0.1", "::1"],
    )
    with TestClient(create_app(settings), base_url="http://127.0.0.1") as client:
        yield client


def stamp(day: int, hour: int) -> datetime:
    return datetime(2025, 4, day, hour, tzinfo=UTC)


@pytest.fixture
def stored(client, monkeypatch):
    asset_id = client.post(
        "/api/assets",
        json={
            "ip_address": "127.0.0.1",
            "display_name": "Lab & <edge> Bağlantı",
            "asset_type": "server",
        },
    ).json()["id"]
    service_id = client.post(
        "/api/services",
        json={
            "name": "Lab service",
            "port": 8443,
            **CONFIRM,
        },
    ).json()["id"]
    probe = Mock(
        side_effect=[
            ("unreachable", "refused"),
            ("reachable", None),
            ("unreachable", "timeout"),
            ("unknown", "socket_error"),
        ]
    )
    monkeypatch.setattr(scope, "probe_tcp_details", probe)
    monkeypatch.setattr(scope, "sleep", Mock())
    engine = client.app.state.engine

    def create_job():
        response = client.post(
            "/api/scan-jobs",
            json={
                "asset_ids": [asset_id],
                "service_ids": [service_id],
                **CONFIRM,
            },
        )
        assert response.status_code == 201
        return response.json()["id"]

    for day, hour in ((1, 1), (2, 1), (2, 2), (3, 1)):
        job_id = create_job()
        assert (
            client.post(f"/api/scan-jobs/{job_id}/start", json=CONFIRM).status_code
            == 202
        )
        with Session(engine) as db, db.begin():
            db.execute(
                update(ScanJob)
                .where(ScanJob.id == job_id)
                .values(
                    created_at=stamp(day, hour),
                    started_at=stamp(day, hour),
                    completed_at=stamp(day, hour + 1),
                )
            )
            db.execute(
                update(ScanResult)
                .where(ScanResult.job_id == job_id)
                .values(
                    checked_at=stamp(day, hour),
                )
            )
    cancel_id = create_job()
    assert (
        client.post(f"/api/scan-jobs/{cancel_id}/cancel", json=CONFIRM).status_code
        == 200
    )
    failed_id = create_job()
    with Session(engine) as db, db.begin():
        db.execute(
            update(ScanJob)
            .where(ScanJob.id == cancel_id)
            .values(
                created_at=stamp(2, 3),
                completed_at=stamp(3, 0),
            )
        )
        db.execute(
            update(ScanJob)
            .where(ScanJob.id == failed_id)
            .values(
                created_at=stamp(3, 2),
                completed_at=stamp(3, 3),
                status="failed",
            )
        )
        db.execute(update(Asset).where(Asset.id == asset_id).values(status="reachable"))
    return asset_id


def test_empty_overview_and_timeline(client):
    response = client.get("/api/analytics/overview", params=PERIOD)
    assert response.status_code == 200
    data = response.json()
    assert data["metrics"]["assets"] == data["metrics"]["approved_services"] == 0
    assert data["metrics"]["completed_jobs"] == 0
    assert data["metrics"]["service_status"] == {
        "reachable": 0,
        "unreachable": 0,
        "unknown": 0,
    }
    assert [row["day"] for row in data["daily"]] == list(PERIOD.values())
    assert data["recent_jobs"] == data["latest_changes"] == []
    assert client.get("/api/analytics/timeline", params=PERIOD).json() == {
        "events": [],
        "next_offset": None,
    }


def test_metrics_date_filter_and_connectivity_changes(client, stored):
    response = client.get("/api/analytics/overview", params=PERIOD)
    assert response.status_code == 200
    data = response.json()
    expected = {
        "assets": 1,
        "asset_status": {"reachable": 1, "unreachable": 0, "unknown": 0},
        "approved_services": 1,
        "completed_jobs": 3,
        "failed_jobs": 1,
        "cancelled_jobs": 1,
        "service_status": {"reachable": 1, "unreachable": 1, "unknown": 1},
        "changes": {"newly_reachable": 1, "became_unreachable": 1},
    }
    assert data["metrics"] == expected
    first, second = data["daily"]
    assert (first["completed"], second["completed"]) == (2, 1)
    assert (first["created"], second["created"]) == (3, 2)
    assert (
        first["newly_reachable"]
        == first["became_unreachable"]
        == second["cancelled"]
        == 1
    )
    assert [row["after"] for row in data["latest_changes"]] == [
        "unreachable",
        "reachable",
    ]
    assert all(
        row["asset_id"] == stored and row["checked_at"].endswith("Z")
        for row in data["latest_changes"]
    )
    empty = client.get(
        "/api/analytics/overview", params={"start": "2025-04-05", "end": "2025-04-05"}
    ).json()
    assert empty["metrics"]["assets"] == 1 and empty["metrics"]["completed_jobs"] == 0


def test_timeline_order_and_paging(client, stored):
    events = []
    offset = 0
    while offset is not None:
        payload = client.get(
            "/api/analytics/timeline",
            params={
                **PERIOD,
                "limit": 3,
                "offset": offset,
            },
        ).json()
        events.extend(payload["events"])
        offset = payload["next_offset"]
    times = [item["occurred_at"] for item in events]
    assert times == sorted(times, reverse=True)
    assert len({(item["kind"], item["source_id"]) for item in events}) == len(events)
    assert {event["kind"] for event in events} == {
        "job_created",
        "job_started",
        "job_completed",
        "job_failed",
        "job_cancelled",
        "newly_reachable",
        "became_unreachable",
    }
    assert client.delete(f"/api/assets/{stored}").status_code == 204
    today = datetime.now(UTC).date().isoformat()
    audit = client.get(
        "/api/analytics/timeline", params={"start": today, "end": today}
    ).json()["events"]
    assert [event["kind"] for event in audit] == ["asset_deleted", "asset_created"]


def pdf_pages(response):
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["cache-control"] == "no-store"
    assert "attachment" in response.headers["content-disposition"]
    return [page.extract_text() for page in PdfReader(BytesIO(response.content)).pages]


def test_full_pdf(client, stored):
    content = "\n".join(pdf_pages(client.get("/api/reports/pdf", params=PERIOD)))
    for section in (
        "Registered asset inventory",
        "Approved service checks",
        "Latest observed connectivity results",
        "Scan job history",
        "Connectivity change summary",
        "Monitoring limitations",
        "Lab & <edge> Bağlantı",
        "Connectivity status is not proof of a security vulnerability",
    ):
        assert section in " ".join(content.split())
    assert "2025-04-01" not in content


def test_empty_pdf_and_report_types(client):
    for kind in ("full", "inventory", "monitoring"):
        text = "\n".join(
            pdf_pages(client.get("/api/reports/pdf", params={**PERIOD, "kind": kind}))
        )
        assert "No records available." in text
        assert ("Registered asset inventory" in text) == (kind != "monitoring")
        assert ("Scan job history" in text) == (kind != "inventory")


def test_pdf_paginates_long_tables_and_uses_literal_text(client):
    with Session(client.app.state.engine) as db, db.begin():
        db.execute(
            insert(Asset),
            [
                {
                    "ip_address": f"192.168.99.{number}",
                    "display_name": f"Asset {number:03d}",
                    "description": "Not included in reports",
                    "asset_type": "<b>Lab</b>",
                    "status": "unknown",
                    "first_seen": stamp(1, 0),
                }
                for number in range(1, 151)
            ],
        )
    pages = pdf_pages(
        client.get("/api/reports/pdf", params={**PERIOD, "kind": "inventory"})
    )
    assert len(pages) >= 4
    inventory_pages = [page for page in pages if "192.168.99." in page]
    assert all(
        "IPaddress" in "".join(page.split()) and "<b>Lab</b>" in "".join(page.split())
        for page in inventory_pages
    )
    assert "Asset 001" in inventory_pages[0] and "Asset 150" in inventory_pages[-1]
    assert "Not included in reports" not in "\n".join(pages)
    assert client.get("/api/analytics/timeline").json()["events"] == []


@pytest.mark.parametrize(
    "route,params",
    [
        ("/api/reports/pdf", {"kind": "unknown"}),
        ("/api/reports/pdf", {"start": "2025-04-30", "end": "2025-04-01"}),
        ("/api/reports/pdf", {"start": "2023-01-01", "end": "2025-04-01"}),
        ("/api/analytics/overview", {"start": "nonsense"}),
        ("/api/analytics/timeline", {"limit": 51}),
    ],
)
def test_invalid_report_parameters(client, route, params):
    assert client.get(route, params=params).status_code == 422
