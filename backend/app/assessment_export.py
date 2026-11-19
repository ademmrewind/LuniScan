import csv
import logging
from io import BytesIO, StringIO
from typing import Literal

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse
from reportlab.lib.pagesizes import A4
from reportlab.platypus import Paragraph, SimpleDocTemplate

from app.assessment_models import AssessmentDetail
from app.assessments import assessment_detail, assessment_row
from app.inventory import DB, AssetID
from app.reporting import add_table, report_slot, report_styles, safe_text
from app.scans import csv_cell

router = APIRouter(prefix="/api/security", tags=["security configuration assessments"])
logger = logging.getLogger(__name__)


def pdf_assessment(data: AssessmentDetail) -> bytes:
    stats = data.summary
    styles = report_styles()
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=44,
        bottomMargin=45,
        title=f"LuniScan | Security Assessment {data.id}",
        author="LuniScan",
    )
    story = [
        Paragraph("LuniScan", styles["Title"]),
        Paragraph(f"Security Assessment #{data.id}", styles["Heading1"]),
        Paragraph(
            "Asset: "
            + safe_text(data.asset_name)
            + " | Service: "
            + safe_text(data.service_name),
            styles["BodyText"],
        ),
        Paragraph(
            safe_text(
                f"{data.protocol.upper()} {data.ip_address}:{data.port}{data.path} | Completed {data.completed_at}"
            ),
            styles["BodyText"],
        ),
        Paragraph(
            "Scope: one authorized endpoint and its configured path. Findings describe observed "
            "configuration. This report does not establish exploitability or complete security coverage.",
            styles["BodyText"],
        ),
    ]
    add_table(
        story,
        styles,
        "Coverage and severity",
        ("Metric", "Count"),
        [
            ("Assessed", stats.assessed),
            ("Inconclusive", stats.inconclusive),
            ("Not applicable", stats.not_applicable),
            *[
                (level, stats.counts.get(level, 0))
                for level in ("informational", "low", "medium", "high")
            ],
        ],
        (370, 130),
    )
    if data.evidence and data.evidence.tls_assessment:
        story.append(
            Paragraph(
                "TLS observation: "
                + safe_text(data.evidence.tls_assessment.replace("_", " ")),
                styles["BodyText"],
            )
        )
    add_table(
        story,
        styles,
        "Configuration observations",
        ("Rule", "Result", "Evidence", "Remediation"),
        [
            (
                item.title,
                item.severity or item.evaluation,
                item.evidence,
                item.recommendation,
            )
            for item in data.observations
        ],
        (115, 75, 135, 175),
    )
    document.build(story)
    return output.getvalue()


@router.get(
    "/assessments/{assessment_id}/export/{format}",
    response_class=Response,
    responses={
        200: {
            "content": {
                "application/pdf": {"schema": {"type": "string", "format": "binary"}},
                "text/csv": {"schema": {"type": "string"}},
                "application/json": {"schema": {"type": "object"}},
            }
        },
    },
)
def export_assessment(
    assessment_id: AssetID, format: Literal["pdf", "json", "csv"], db: DB
) -> Response:
    row = assessment_row(db, assessment_id)
    if row.status != "completed" or row.summary is None:
        raise HTTPException(409, "Only completed assessments can be exported.")
    data = assessment_detail(db, row)
    headers = {
        "Content-Disposition": f'attachment; filename="security-assessment-{assessment_id}.{format}"'
    }
    if format == "json":
        return JSONResponse(data.model_dump(mode="json"), headers=headers)
    if format == "pdf":
        if not report_slot.acquire(blocking=False):
            raise HTTPException(429, "A report is already being generated.")
        try:
            return Response(
                pdf_assessment(data), media_type="application/pdf", headers=headers
            )
        except Exception:
            logger.error(
                "Unable to render security assessment report %s", assessment_id
            )
            raise HTTPException(500, "Unable to generate the PDF report.") from None
        finally:
            report_slot.release()
    output = StringIO(newline="")
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    writer.writerow(
        (
            "Assessment",
            "Asset",
            "Service",
            "Rule",
            "Evaluation",
            "Severity",
            "Evidence",
            "Remediation",
        )
    )
    for item in data.observations:
        writer.writerow(
            [
                csv_cell(str(value))
                for value in (
                    data.id,
                    data.asset_name,
                    data.service_name,
                    item.title,
                    item.evaluation,
                    item.severity or "",
                    item.evidence,
                    item.recommendation,
                )
            ]
        )
    return Response(output.getvalue(), media_type="text/csv", headers=headers)
