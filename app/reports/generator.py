"""Automated incident and forensic report generator in JSON, CSV, and PDF."""
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from app.database.db import SessionLocal
from app.database.models import IncidentModel, AlertModel, FileEventModel

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class ReportGenerator:
    """Exports forensic incident summaries into structured reports."""

    @staticmethod
    def generate_json_report(incident_id: Optional[int] = None) -> str:
        session = SessionLocal()
        try:
            query = session.query(IncidentModel)
            if incident_id:
                query = query.filter(IncidentModel.id == incident_id)
            incidents = query.all()

            data = [
                {
                    "incident_id": inc.id,
                    "timestamp": inc.timestamp.isoformat() if inc.timestamp else None,
                    "threat_score": inc.threat_score,
                    "status": inc.status,
                    "affected_files_count": inc.affected_files_count,
                    "suspect_process": inc.suspect_process,
                    "suspect_pid": inc.suspect_pid,
                    "evidence_path": inc.evidence_path,
                    "mitigation_action": inc.mitigation_action,
                }
                for inc in incidents
            ]

            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            file_path = REPORTS_DIR / f"incident_report_{ts}.json"
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)

            return str(file_path.resolve())
        finally:
            session.close()

    @staticmethod
    def generate_csv_report() -> str:
        session = SessionLocal()
        try:
            alerts = session.query(AlertModel).all()
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            file_path = REPORTS_DIR / f"alerts_summary_{ts}.csv"

            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Alert ID", "Timestamp", "Severity", "Score", "Rule Triggered", "Suspect Process", "PID"])
                for a in alerts:
                    writer.writerow([a.id, a.timestamp, a.severity, a.score, a.rule_name, a.suspect_process, a.suspect_pid])

            return str(file_path.resolve())
        finally:
            session.close()

    @staticmethod
    def generate_pdf_report(incident_id: Optional[int] = None) -> str:
        session = SessionLocal()
        try:
            query = session.query(IncidentModel)
            if incident_id:
                query = query.filter(IncidentModel.id == incident_id)
            incidents = query.all()

            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            file_path = REPORTS_DIR / f"SOC_Incident_Report_{ts}.pdf"

            doc = SimpleDocTemplate(str(file_path), pagesize=letter)
            styles = getSampleStyleSheet()
            elements = []

            # Title
            title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor("#0f172a"))
            elements.append(Paragraph("RDRS Security Operations — Forensic Incident Report", title_style))
            elements.append(Spacer(1, 12))

            # Meta Details
            body_style = styles['Normal']
            elements.append(Paragraph(f"<b>Generated At:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style))
            elements.append(Paragraph(f"<b>Total Incidents Documented:</b> {len(incidents)}", body_style))
            elements.append(Spacer(1, 16))

            # Table Header & Data
            table_data = [["ID", "Timestamp", "Score", "Suspect", "Action"]]
            for inc in incidents:
                time_str = inc.timestamp.strftime("%H:%M:%S") if inc.timestamp else "N/A"
                table_data.append([
                    str(inc.id),
                    time_str,
                    f"{inc.threat_score}/100",
                    f"{inc.suspect_process} ({inc.suspect_pid})",
                    inc.mitigation_action[:25] + "..." if len(inc.mitigation_action) > 25 else inc.mitigation_action
                ])

            if len(table_data) == 1:
                table_data.append(["-", "No incidents recorded yet", "-", "-", "-"])

            t = Table(table_data, colWidths=[30, 70, 70, 150, 160])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))

            elements.append(t)
            doc.build(elements)
            return str(file_path.resolve())
        finally:
            session.close()
