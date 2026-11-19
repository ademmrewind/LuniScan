import logging
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from threading import BoundedSemaphore
from typing import Literal
from unicodedata import category
from xml.sax.saxutils import escape

import reportlab
from fastapi import APIRouter, HTTPException, Response
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    LongTable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)
from sqlalchemy import func, select

from app.analytics import (
    Range,
    changes_query,
    completed_results,
    metrics,
    recent_jobs_query,
)
from app.inventory import DB, Asset
from app.monitor_models import MonitorAlert, MonitorCheck, MonitorProfile
from app.scan_models import ScanResult, Service, utc

router = APIRouter(prefix="/api/reports", tags=["reporting"])
ReportType = Literal["full", "inventory", "monitoring"]
ROW_LIMIT = 1000
report_slot = BoundedSemaphore(1)
logger = logging.getLogger(__name__)
font_dir = Path(reportlab.__file__).parent / "fonts"
table_font = TTFont("LuniScanSans", str(font_dir / "Vera.ttf"))
pdfmetrics.registerFont(table_font)
pdfmetrics.registerFont(TTFont("LuniScanSans-Bold", str(font_dir / "VeraBd.ttf")))


def safe_text(value: object) -> str:
    if isinstance(value, datetime):
        value = utc(value).strftime("%Y-%m-%d %H:%M:%S")
    text = str(value) if value is not None else "—"
    text = "".join(
        " " if char.isspace() else char
        for char in text[:240]
        if char.isspace() or not category(char).startswith("C")
    )
    return escape(
        "".join(
            char if ord(char) in table_font.face.charToGlyph else "?" for char in text
        )
    )


def add_table(story, styles, title, columns, rows, widths) -> None:
    story.append(Paragraph(title, styles["Heading2"]))
    if not rows:
        story.append(Paragraph("No records available.", styles["BodyText"]))
        return
    content = [
        [Paragraph(safe_text(value), styles["TableHeader"]) for value in columns]
    ]
    content.extend(
        [Paragraph(safe_text(value), styles["TableCell"]) for value in row]
        for row in rows[:ROW_LIMIT]
    )
    table = LongTable(content, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14263c")),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#edf3f8")],
                ),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend([table, Spacer(1, 10)])
    if len(rows) > ROW_LIMIT:
        story.append(
            Paragraph(
                f"Showing the first {ROW_LIMIT:,} rows of this section.",
                styles["BodyText"],
            )
        )


def report_rows(db: DB, period: Range, kind: ReportType):
    sections = []
    if kind in ("full", "inventory"):
        assets = select(
            Asset.id,
            Asset.display_name,
            Asset.ip_address,
            Asset.asset_type,
            Asset.status,
            Asset.hostname,
            Asset.operating_system,
        ).order_by(Asset.id)
        sections.append(
            (
                "Registered asset inventory",
                ("ID", "Asset", "IP address", "Type", "Status", "Hostname", "OS"),
                db.execute(assets.limit(ROW_LIMIT + 1)).all(),
                (30, 100, 98, 65, 64, 76, 74),
            )
        )
    services = (
        select(Service.id, Service.name, Service.port)
        .where(Service.active)
        .order_by(Service.id)
    )
    sections.append(
        (
            "Approved service checks",
            ("ID", "Service", "TCP port"),
            db.execute(services.limit(ROW_LIMIT + 1)).all(),
            (60, 347, 100),
        )
    )
    if kind in ("full", "monitoring"):
        ranked = (
            completed_results(period)
            .with_only_columns(
                ScanResult.asset_name,
                ScanResult.ip_address,
                ScanResult.service_name,
                ScanResult.port,
                ScanResult.status,
                ScanResult.checked_at,
                ScanResult.job_id,
                ScanResult.id,
                func.row_number()
                .over(
                    partition_by=(
                        ScanResult.asset_id,
                        ScanResult.service_id,
                        ScanResult.address_revision,
                    ),
                    order_by=ScanResult.id.desc(),
                )
                .label("rank"),
                maintain_column_froms=True,
            )
            .subquery()
        )
        latest = (
            select(
                ranked.c.asset_name,
                ranked.c.ip_address,
                ranked.c.service_name,
                ranked.c.port,
                ranked.c.status,
                ranked.c.checked_at,
                ranked.c.job_id,
            )
            .where(ranked.c.rank == 1)
            .order_by(ranked.c.checked_at.desc(), ranked.c.id.desc())
        )
        sections.append(
            (
                "Latest observed connectivity results",
                (
                    "Asset",
                    "IP address",
                    "Service",
                    "Port",
                    "Status",
                    "Checked (UTC)",
                    "Job",
                ),
                db.execute(latest.limit(ROW_LIMIT + 1)).all(),
                (94, 85, 90, 40, 63, 88, 47),
            )
        )
        jobs = recent_jobs_query(period).subquery()
        job_rows = select(
            jobs.c.id,
            jobs.c.status,
            jobs.c.created_at,
            jobs.c.started_at,
            jobs.c.completed_at,
            jobs.c.done_count,
            jobs.c.check_count,
        ).order_by(
            func.coalesce(
                jobs.c.completed_at, jobs.c.started_at, jobs.c.created_at
            ).desc(),
            jobs.c.id.desc(),
        )
        sections.append(
            (
                "Scan job history",
                (
                    "ID",
                    "Status",
                    "Created (UTC)",
                    "Started (UTC)",
                    "Finished (UTC)",
                    "Done",
                    "Planned",
                ),
                db.execute(job_rows.limit(ROW_LIMIT + 1)).all(),
                (39, 67, 102, 102, 103, 40, 54),
            )
        )
        outcomes = (
            select(MonitorCheck.health, func.count())
            .where(period.includes(MonitorCheck.checked_at))
            .group_by(MonitorCheck.health)
        )
        checks = (
            select(
                MonitorProfile.name,
                MonitorCheck.health,
                MonitorCheck.http_status,
                MonitorCheck.duration_ms,
                MonitorCheck.checked_at,
            )
            .join(MonitorProfile)
            .where(period.includes(MonitorCheck.checked_at))
            .order_by(MonitorCheck.id.desc())
        )
        cert_ids = (
            select(func.max(MonitorCheck.id))
            .where(MonitorCheck.certificate_state.is_not(None))
            .group_by(MonitorCheck.profile_id)
        )
        certificates = (
            select(
                MonitorProfile.name,
                MonitorCheck.certificate_state,
                func.json_extract(MonitorCheck.result, "$.certificate.expires_at"),
                MonitorCheck.checked_at,
            )
            .join(MonitorProfile)
            .where(
                MonitorProfile.enabled,
                MonitorProfile.archived.is_(False),
                MonitorCheck.id.in_(cert_ids),
            )
            .order_by(MonitorProfile.id)
        )
        active = (
            select(
                MonitorProfile.name,
                MonitorAlert.kind,
                MonitorAlert.severity,
                MonitorAlert.status,
                MonitorAlert.created_at,
            )
            .join(MonitorProfile)
            .where(MonitorAlert.resolved_at.is_(None))
            .order_by(MonitorAlert.id.desc())
        )
        for title, labels, query, widths in (
            (
                "Service health summary",
                ("Health", "Observed checks"),
                outcomes,
                (240, 260),
            ),
            (
                "Service availability and HTTP monitoring history",
                ("Service", "Health", "HTTP", "Duration (ms)", "Checked UTC"),
                checks,
                (166, 74, 42, 75, 143),
            ),
            (
                "Latest TLS certificate states",
                ("Service", "Recorded state", "Expires (UTC)", "Observed (UTC)"),
                certificates,
                (170, 110, 115, 105),
            ),
            (
                "Open monitoring alerts",
                ("Service", "Alert", "Severity", "Status", "Created UTC"),
                active,
                (130, 115, 58, 83, 114),
            ),
        ):
            sections.append(
                (title, labels, db.execute(query.limit(ROW_LIMIT + 1)).all(), widths)
            )
    return sections


def render_pdf(summary, sections, period, kind: ReportType) -> bytes:
    output = BytesIO()
    styles = getSampleStyleSheet()
    styles["Title"].textColor = colors.HexColor("#123753")
    styles.add(
        ParagraphStyle(
            "TableCell",
            fontName="LuniScanSans",
            fontSize=8,
            leading=10,
            splitLongWords=True,
        )
    )
    styles.add(
        ParagraphStyle(
            "TableHeader",
            parent=styles["TableCell"],
            fontName="LuniScanSans-Bold",
            textColor=colors.white,
        )
    )
    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=44,
        bottomMargin=45,
        title="LuniScan | " + kind.title() + " Report",
        author="LuniScan",
    )
    story = [
        Paragraph("LuniScan", styles["Title"]),
        Paragraph(kind.title() + " report", styles["Heading1"]),
        Paragraph(
            "Generated " + datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            styles["BodyText"],
        ),
        Paragraph(
            f"Reporting period (UTC): {period.start} to {period.end}",
            styles["BodyText"],
        ),
    ]
    add_table(
        story,
        styles,
        "Summary statistics",
        ("Metric", "Count"),
        [
            ("Registered assets", summary.assets),
            ("Reachable assets", summary.asset_status.reachable),
            ("Unreachable assets", summary.asset_status.unreachable),
            ("Unknown asset status", summary.asset_status.unknown),
            ("Approved services", summary.approved_services),
            ("Completed scan jobs", summary.completed_jobs),
            ("Failed scan jobs", summary.failed_jobs),
            ("Cancelled scan jobs", summary.cancelled_jobs),
            ("Reachable service checks", summary.service_status.reachable),
            ("Unreachable service checks", summary.service_status.unreachable),
            ("Unknown service checks", summary.service_status.unknown),
        ],
        (407, 100),
    )
    add_table(
        story,
        styles,
        "Connectivity change summary",
        ("Observed transition", "Count"),
        [
            ("Newly reachable", summary.changes.newly_reachable),
            ("Became unreachable", summary.changes.became_unreachable),
        ],
        (407, 100),
    )
    for section in sections:
        add_table(story, styles, *section)
    story.extend(
        [
            Paragraph("Monitoring limitations", styles["Heading2"]),
            Paragraph(
                "Connectivity status is not proof of a security vulnerability. An observation describes "
                "one approved TCP endpoint at check time. Unknown and first observations are excluded "
                "from change totals. Inventory and service approval data are current snapshots. "
                "Only completed jobs contribute connectivity results.",
                styles["BodyText"],
            ),
        ]
    )

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#40576d"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(40, 25, "LuniScan | Authorized network monitoring")
        canvas.drawRightString(A4[0] - 40, 25, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()


@router.get(
    "/pdf",
    response_class=Response,
    responses={
        200: {
            "content": {
                "application/pdf": {"schema": {"type": "string", "format": "binary"}}
            }
        },
        429: {"description": "A report is already being generated"},
    },
)
def download_report(db: DB, period: Range, kind: ReportType = "full") -> Response:
    """Download a PDF using current inventory and completed observations from the selected UTC dates."""
    if not report_slot.acquire(blocking=False):
        raise HTTPException(
            429, "A report is already being generated. Try again shortly."
        )
    try:
        db.connection().exec_driver_sql("BEGIN")
        summary = metrics(db, period, changes_query(period))
        sections = report_rows(db, period, kind)
        db.rollback()
        try:
            pdf = render_pdf(summary, sections, period, kind)
        except Exception:
            logger.error("Unable to render a LuniScan PDF report")
            raise HTTPException(500, "Unable to generate the PDF report.") from None
    finally:
        report_slot.release()
    return Response(
        pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="luniscan-{kind}-{period.start}-{period.end}.pdf"',
            "Cache-Control": "no-store",
        },
    )
