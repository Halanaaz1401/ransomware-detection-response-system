"""RDRS incident and forensic report generator."""

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.database.db import SessionLocal
from app.database.models import (
    IncidentModel,
    AlertModel,
    FileEventModel,
)


REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class ReportGenerator:
    """Generate structured RDRS incident reports."""

    @staticmethod
    def _utc_now_naive() -> datetime:
        """Return current UTC time as a timezone-naive datetime for SQLite."""
        return datetime.now(timezone.utc).replace(tzinfo=None)

    @staticmethod
    def _format_timestamp(value) -> Optional[str]:
        """Convert a database timestamp to an ISO-8601 UTC string."""
        if value is None:
            return None

        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        return value.isoformat()

    @staticmethod
    def _recommendations(incident: IncidentModel) -> list[str]:
        """Generate defensive recommendations based on incident severity."""

        recommendations = [
            "Review the affected files and preserved evidence.",
            "Verify the identity and legitimacy of the suspected process.",
            "Inspect recent filesystem activity around the incident timestamp.",
            "Review system and audit logs for related activity.",
        ]

        if incident.threat_score >= 70:
            recommendations.extend(
                [
                    "Keep the affected host under investigation until the activity is understood.",
                    "Validate that simulation mode remains enabled during testing.",
                    "Restore files only from trusted backups after investigation.",
                ]
            )

        return recommendations

    @staticmethod
    def _incident_events(
        session,
        incident: IncidentModel,
        window_seconds: int = 120,
    ) -> list[FileEventModel]:
        """Return filesystem events surrounding an incident."""

        if not incident.timestamp:
            return []

        start_time = incident.timestamp - timedelta(
            seconds=window_seconds
        )
        end_time = incident.timestamp + timedelta(
            seconds=window_seconds
        )

        return (
            session.query(FileEventModel)
            .filter(
                FileEventModel.timestamp >= start_time,
                FileEventModel.timestamp <= end_time,
            )
            .order_by(FileEventModel.timestamp.asc())
            .all()
        )

    @staticmethod
    def _affected_files(events: list[FileEventModel]) -> list[str]:
        """Build a unique affected-file list from filesystem events."""

        files = []

        for event in events:
            candidates = [
                event.src_path,
                event.dest_path,
            ]

            for path in candidates:
                if path and path not in files:
                    files.append(path)

        return files

    @staticmethod
    def _build_incident_data(
        session,
        incident: IncidentModel,
    ) -> dict:
        """Build a complete structured representation of an incident."""

        events = ReportGenerator._incident_events(
            session,
            incident,
        )

        affected_files = ReportGenerator._affected_files(events)

        timeline = [
            {
                "timestamp": ReportGenerator._format_timestamp(
                    event.timestamp
                ),
                "event_type": event.event_type,
                "source_path": event.src_path,
                "destination_path": event.dest_path,
                "file_extension": event.file_extension,
                "entropy": event.entropy,
            }
            for event in events
        ]

        return {
            "incident_id": incident.id,
            "timestamp": ReportGenerator._format_timestamp(
                incident.timestamp
            ),
            "threat_score": incident.threat_score,
            "severity": (
                "Critical"
                if incident.threat_score >= 70
                else "Warning"
            ),
            "status": incident.status,
            "affected_files_count": max(
                incident.affected_files_count or 0,
                len(affected_files),
            ),
            "affected_files": affected_files,
            "suspect_process": incident.suspect_process,
            "suspect_pid": incident.suspect_pid,
            "evidence_path": incident.evidence_path,
            "mitigation_action": incident.mitigation_action,
            "timeline": timeline,
            "recommendations": ReportGenerator._recommendations(
                incident
            ),
        }

    @staticmethod
    def _get_incidents(
        session,
        incident_id: Optional[int] = None,
    ) -> list[IncidentModel]:
        """Retrieve incidents, optionally filtered by ID."""

        query = session.query(IncidentModel)

        if incident_id is not None:
            query = query.filter(
                IncidentModel.id == incident_id
            )

        return query.order_by(
            IncidentModel.timestamp.asc()
        ).all()

    @staticmethod
    def generate_json_report(
        incident_id: Optional[int] = None,
    ) -> str:
        """Generate a complete JSON forensic incident report."""

        session = SessionLocal()

        try:
            incidents = ReportGenerator._get_incidents(
                session,
                incident_id,
            )

            data = {
                "report_type": "RDRS Forensic Incident Report",
                "generated_at": (
                    datetime.now(timezone.utc).isoformat()
                ),
                "incident_count": len(incidents),
                "incidents": [
                    ReportGenerator._build_incident_data(
                        session,
                        incident,
                    )
                    for incident in incidents
                ],
            }

            timestamp = datetime.now(
                timezone.utc
            ).strftime("%Y%m%d_%H%M%S")

            file_path = (
                REPORTS_DIR
                / f"incident_report_{timestamp}.json"
            )

            with file_path.open(
                "w",
                encoding="utf-8",
            ) as report_file:
                json.dump(
                    data,
                    report_file,
                    indent=4,
                )

            return str(file_path.resolve())

        finally:
            session.close()

    @staticmethod
    def generate_csv_report() -> str:
        """Generate a CSV forensic timeline report."""

        session = SessionLocal()

        try:
            incidents = ReportGenerator._get_incidents(
                session
            )

            timestamp = datetime.now(
                timezone.utc
            ).strftime("%Y%m%d_%H%M%S")

            file_path = (
                REPORTS_DIR
                / f"incident_timeline_{timestamp}.csv"
            )

            with file_path.open(
                "w",
                newline="",
                encoding="utf-8",
            ) as report_file:

                fieldnames = [
                    "incident_id",
                    "incident_timestamp",
                    "threat_score",
                    "severity",
                    "status",
                    "suspect_process",
                    "suspect_pid",
                    "evidence_path",
                    "mitigation_action",
                    "event_timestamp",
                    "event_type",
                    "source_path",
                    "destination_path",
                    "file_extension",
                    "entropy",
                    "affected_file",
                ]

                writer = csv.DictWriter(
                    report_file,
                    fieldnames=fieldnames,
                )

                writer.writeheader()

                for incident in incidents:
                    incident_data = (
                        ReportGenerator._build_incident_data(
                            session,
                            incident,
                        )
                    )

                    timeline = incident_data["timeline"]
                    affected_files = incident_data[
                        "affected_files"
                    ]

                    if not timeline:
                        writer.writerow(
                            {
                                "incident_id": incident.id,
                                "incident_timestamp": incident_data[
                                    "timestamp"
                                ],
                                "threat_score": incident.threat_score,
                                "severity": incident_data[
                                    "severity"
                                ],
                                "status": incident.status,
                                "suspect_process": incident.suspect_process,
                                "suspect_pid": incident.suspect_pid,
                                "evidence_path": incident.evidence_path,
                                "mitigation_action": incident.mitigation_action,
                            }
                        )
                        continue

                    for index, event in enumerate(timeline):
                        affected_file = (
                            affected_files[index]
                            if index < len(affected_files)
                            else ""
                        )

                        writer.writerow(
                            {
                                "incident_id": incident.id,
                                "incident_timestamp": incident_data[
                                    "timestamp"
                                ],
                                "threat_score": incident.threat_score,
                                "severity": incident_data[
                                    "severity"
                                ],
                                "status": incident.status,
                                "suspect_process": incident.suspect_process,
                                "suspect_pid": incident.suspect_pid,
                                "evidence_path": incident.evidence_path,
                                "mitigation_action": incident.mitigation_action,
                                "event_timestamp": event[
                                    "timestamp"
                                ],
                                "event_type": event[
                                    "event_type"
                                ],
                                "source_path": event[
                                    "source_path"
                                ],
                                "destination_path": event[
                                    "destination_path"
                                ],
                                "file_extension": event[
                                    "file_extension"
                                ],
                                "entropy": event[
                                    "entropy"
                                ],
                                "affected_file": affected_file,
                            }
                        )

            return str(file_path.resolve())

        finally:
            session.close()

    @staticmethod
    def generate_pdf_report(
        incident_id: Optional[int] = None,
    ) -> str:
        """Generate a readable SOC forensic incident PDF."""

        session = SessionLocal()

        try:
            incidents = ReportGenerator._get_incidents(
                session,
                incident_id,
            )

            timestamp = datetime.now(
                timezone.utc
            ).strftime("%Y%m%d_%H%M%S")

            file_path = (
                REPORTS_DIR
                / f"SOC_Incident_Report_{timestamp}.pdf"
            )

            document = SimpleDocTemplate(
                str(file_path),
                pagesize=letter,
                rightMargin=36,
                leftMargin=36,
                topMargin=36,
                bottomMargin=36,
            )

            styles = getSampleStyleSheet()

            title_style = ParagraphStyle(
                "RDRSTitle",
                parent=styles["Heading1"],
                fontSize=18,
                leading=22,
                spaceAfter=12,
            )

            heading_style = ParagraphStyle(
                "RDRSHeading",
                parent=styles["Heading2"],
                fontSize=13,
                leading=16,
                spaceBefore=12,
                spaceAfter=8,
            )

            body_style = ParagraphStyle(
                "RDRSBody",
                parent=styles["BodyText"],
                fontSize=9,
                leading=12,
                spaceAfter=5,
            )

            small_style = ParagraphStyle(
                "RDRSSmall",
                parent=styles["BodyText"],
                fontSize=7,
                leading=9,
            )

            elements = []

            elements.append(
                Paragraph(
                    "RDRS Security Operations — Forensic Incident Report",
                    title_style,
                )
            )

            elements.append(
                Paragraph(
                    "<b>Generated:</b> "
                    + datetime.now(
                        timezone.utc
                    ).strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    ),
                    body_style,
                )
            )

            elements.append(
                Paragraph(
                    f"<b>Incidents documented:</b> {len(incidents)}",
                    body_style,
                )
            )

            elements.append(Spacer(1, 12))

            if not incidents:
                elements.append(
                    Paragraph(
                        "No incidents are currently recorded.",
                        body_style,
                    )
                )

            for incident in incidents:
                data = ReportGenerator._build_incident_data(
                    session,
                    incident,
                )

                elements.append(
                    Paragraph(
                        f"Incident #{incident.id}",
                        heading_style,
                    )
                )

                summary_data = [
                    ["Field", "Value"],
                    [
                        "Timestamp",
                        str(data["timestamp"]),
                    ],
                    [
                        "Threat Score",
                        f'{data["threat_score"]}/100',
                    ],
                    [
                        "Severity",
                        data["severity"],
                    ],
                    [
                        "Status",
                        str(data["status"]),
                    ],
                    [
                        "Suspect Process",
                        f'{data["suspect_process"]} '
                        f'(PID {data["suspect_pid"]})',
                    ],
                    [
                        "Evidence",
                        str(data["evidence_path"]),
                    ],
                    [
                        "Mitigation",
                        str(data["mitigation_action"]),
                    ],
                ]

                summary_table = Table(
                    summary_data,
                    colWidths=[120, 390],
                )

                summary_table.setStyle(
                    TableStyle(
                        [
                            (
                                "BACKGROUND",
                                (0, 0),
                                (-1, 0),
                                colors.HexColor("#1e293b"),
                            ),
                            (
                                "TEXTCOLOR",
                                (0, 0),
                                (-1, 0),
                                colors.white,
                            ),
                            (
                                "FONTNAME",
                                (0, 0),
                                (-1, 0),
                                "Helvetica-Bold",
                            ),
                            (
                                "GRID",
                                (0, 0),
                                (-1, -1),
                                0.5,
                                colors.HexColor("#cbd5e1"),
                            ),
                            (
                                "VALIGN",
                                (0, 0),
                                (-1, -1),
                                "TOP",
                            ),
                            (
                                "FONTSIZE",
                                (0, 0),
                                (-1, -1),
                                8,
                            ),
                            (
                                "BOTTOMPADDING",
                                (0, 0),
                                (-1, -1),
                                5,
                            ),
                            (
                                "TOPPADDING",
                                (0, 0),
                                (-1, -1),
                                5,
                            ),
                        ]
                    )
                )

                elements.append(summary_table)

                elements.append(
                    Paragraph(
                        "Affected Files",
                        heading_style,
                    )
                )

                if data["affected_files"]:
                    for path in data["affected_files"][:100]:
                        elements.append(
                            Paragraph(
                                escape(str(path)),
                                small_style,
                            )
                        )
                else:
                    elements.append(
                        Paragraph(
                            "No affected files were reconstructed from "
                            "the stored event timeline.",
                            body_style,
                        )
                    )

                elements.append(
                    Paragraph(
                        "Event Timeline",
                        heading_style,
                    )
                )

                timeline_rows = [
                    [
                        "Time",
                        "Event",
                        "Source",
                        "Destination",
                        "Entropy",
                    ]
                ]

                for event in data["timeline"][:100]:
                    timeline_rows.append(
                        [
                            str(event["timestamp"]),
                            str(event["event_type"]),
                            str(event["source_path"]),
                            str(event["destination_path"] or ""),
                            str(event["entropy"]),
                        ]
                    )

                if len(timeline_rows) == 1:
                    timeline_rows.append(
                        [
                            "-",
                            "No events found",
                            "-",
                            "-",
                            "-",
                        ]
                    )

                timeline_table = Table(
                    timeline_rows,
                    colWidths=[
                        80,
                        55,
                        145,
                        145,
                        45,
                    ],
                    repeatRows=1,
                )

                timeline_table.setStyle(
                    TableStyle(
                        [
                            (
                                "BACKGROUND",
                                (0, 0),
                                (-1, 0),
                                colors.HexColor("#334155"),
                            ),
                            (
                                "TEXTCOLOR",
                                (0, 0),
                                (-1, 0),
                                colors.white,
                            ),
                            (
                                "FONTNAME",
                                (0, 0),
                                (-1, 0),
                                "Helvetica-Bold",
                            ),
                            (
                                "FONTSIZE",
                                (0, 0),
                                (-1, -1),
                                6,
                            ),
                            (
                                "GRID",
                                (0, 0),
                                (-1, -1),
                                0.4,
                                colors.HexColor("#cbd5e1"),
                            ),
                            (
                                "VALIGN",
                                (0, 0),
                                (-1, -1),
                                "TOP",
                            ),
                        ]
                    )
                )

                elements.append(timeline_table)

                elements.append(
                    Paragraph(
                        "Recommendations",
                        heading_style,
                    )
                )

                for recommendation in data[
                    "recommendations"
                ]:
                    elements.append(
                        Paragraph(
                            "• "
                            + escape(
                                recommendation
                            ),
                            body_style,
                        )
                    )

                elements.append(Spacer(1, 16))

            document.build(elements)

            return str(file_path.resolve())

        finally:
            session.close()
