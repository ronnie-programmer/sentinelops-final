import os
from datetime import datetime
from typing import List
import csv
import io

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from database import get_db
from models import ComplianceReport
from schemas import ComplianceReportGenerate, ComplianceReportOut

router = APIRouter(prefix="/api/compliance", tags=["compliance"])

# ── Static compliance control data ──────────────────────────────────────────

NIST_CONTROLS = [
    {"id": "AC-1", "name": "Access Control Policy", "category": "Access Control", "status": "Passing", "description": "Organizational access control policy and procedures documented and enforced.", "last_assessed": "2026-03-15", "owner": "IT Security"},
    {"id": "AC-2", "name": "Account Management", "category": "Access Control", "status": "Passing", "description": "User accounts managed through automated provisioning and quarterly reviews.", "last_assessed": "2026-03-20", "owner": "IAM Team"},
    {"id": "AC-3", "name": "Access Enforcement", "category": "Access Control", "status": "Passing", "description": "Role-based access control enforced across all systems.", "last_assessed": "2026-03-20", "owner": "IAM Team"},
    {"id": "AC-17", "name": "Remote Access", "category": "Access Control", "status": "In Review", "description": "Remote access policies under review following VPN infrastructure upgrade.", "last_assessed": "2026-02-28", "owner": "Network Security"},
    {"id": "AU-2", "name": "Event Logging", "category": "Audit and Accountability", "status": "Passing", "description": "Comprehensive event logging enabled across all critical systems.", "last_assessed": "2026-03-10", "owner": "SOC Team"},
    {"id": "AU-6", "name": "Audit Review and Reporting", "category": "Audit and Accountability", "status": "Passing", "description": "Daily automated audit log review with SIEM correlation rules.", "last_assessed": "2026-03-25", "owner": "SOC Team"},
    {"id": "AU-9", "name": "Protection of Audit Information", "category": "Audit and Accountability", "status": "Failing", "description": "Audit logs not yet replicated to immutable storage. Remediation in progress.", "last_assessed": "2026-03-01", "owner": "Infrastructure"},
    {"id": "CA-7", "name": "Continuous Monitoring", "category": "Assessment and Authorization", "status": "Passing", "description": "Continuous monitoring program active with automated scanning.", "last_assessed": "2026-03-28", "owner": "SOC Team"},
    {"id": "CM-6", "name": "Configuration Settings", "category": "Configuration Management", "status": "In Review", "description": "Baseline configuration settings being standardized across cloud workloads.", "last_assessed": "2026-02-15", "owner": "DevOps"},
    {"id": "CM-8", "name": "System Component Inventory", "category": "Configuration Management", "status": "Passing", "description": "Asset inventory maintained with automated discovery and CMDB integration.", "last_assessed": "2026-03-22", "owner": "IT Operations"},
    {"id": "IA-2", "name": "Identification and Authentication", "category": "Identification and Authentication", "status": "Passing", "description": "Multi-factor authentication enforced for all privileged accounts.", "last_assessed": "2026-03-18", "owner": "IAM Team"},
    {"id": "IA-5", "name": "Authenticator Management", "category": "Identification and Authentication", "status": "Failing", "description": "Password rotation policy not enforced on 12% of service accounts.", "last_assessed": "2026-03-05", "owner": "IAM Team"},
    {"id": "IR-4", "name": "Incident Handling", "category": "Incident Response", "status": "Passing", "description": "Incident response playbooks maintained and tested quarterly.", "last_assessed": "2026-03-12", "owner": "SOC Team"},
    {"id": "IR-5", "name": "Incident Monitoring", "category": "Incident Response", "status": "Passing", "description": "24/7 SOC monitoring with automated alerting and escalation paths.", "last_assessed": "2026-03-28", "owner": "SOC Team"},
    {"id": "RA-5", "name": "Vulnerability Monitoring", "category": "Risk Assessment", "status": "Passing", "description": "Weekly automated vulnerability scans with risk-based prioritization.", "last_assessed": "2026-03-25", "owner": "Security Engineering"},
    {"id": "SC-7", "name": "Boundary Protection", "category": "System and Communications", "status": "Passing", "description": "Network segmentation and firewall rules reviewed and enforced.", "last_assessed": "2026-03-15", "owner": "Network Security"},
    {"id": "SC-28", "name": "Protection of Information at Rest", "category": "System and Communications", "status": "In Review", "description": "Encryption at rest audit underway for legacy database systems.", "last_assessed": "2026-02-20", "owner": "Data Security"},
    {"id": "SI-3", "name": "Malicious Code Protection", "category": "System and Information Integrity", "status": "Passing", "description": "EDR deployed on 98.7% of endpoints with real-time threat prevention.", "last_assessed": "2026-03-28", "owner": "Endpoint Security"},
    {"id": "SI-4", "name": "System Monitoring", "category": "System and Information Integrity", "status": "Passing", "description": "SIEM and UEBA solutions active with behavioral analytics.", "last_assessed": "2026-03-28", "owner": "SOC Team"},
    {"id": "SI-7", "name": "Software, Firmware, and Information Integrity", "category": "System and Information Integrity", "status": "Failing", "description": "File integrity monitoring not deployed on 3 legacy application servers.", "last_assessed": "2026-03-10", "owner": "Security Engineering"},
]

SOC2_CONTROLS = [
    {"id": "CC1.1", "name": "COSO Principle 1 - Integrity and Ethics", "category": "Control Environment", "status": "Passing", "description": "Board and management demonstrate commitment to integrity and ethical values.", "last_assessed": "2026-03-01", "owner": "Compliance"},
    {"id": "CC2.1", "name": "Information and Communication", "category": "Communication and Information", "status": "Passing", "description": "Security policies communicated to all personnel through annual training.", "last_assessed": "2026-03-15", "owner": "HR / Compliance"},
    {"id": "CC3.1", "name": "Risk Assessment - Objectives", "category": "Risk Assessment", "status": "Passing", "description": "Annual risk assessment completed with documented risk register.", "last_assessed": "2026-02-28", "owner": "Risk Management"},
    {"id": "CC5.1", "name": "Control Activities - Policies", "category": "Control Activities", "status": "In Review", "description": "Control activity policies being updated to reflect new cloud architecture.", "last_assessed": "2026-02-10", "owner": "Compliance"},
    {"id": "CC6.1", "name": "Logical Access Controls", "category": "Logical and Physical Access", "status": "Passing", "description": "Logical access controls restrict access to production systems.", "last_assessed": "2026-03-20", "owner": "IAM Team"},
    {"id": "CC6.6", "name": "Network and Infrastructure Security", "category": "Logical and Physical Access", "status": "Passing", "description": "Network security controls prevent unauthorized external access.", "last_assessed": "2026-03-15", "owner": "Network Security"},
    {"id": "CC6.7", "name": "Transmission of Confidential Information", "category": "Logical and Physical Access", "status": "Passing", "description": "All data in transit encrypted using TLS 1.2+.", "last_assessed": "2026-03-22", "owner": "Data Security"},
    {"id": "CC7.1", "name": "System Operations - Detection", "category": "System Operations", "status": "Passing", "description": "Automated detection of configuration changes and anomalous activity.", "last_assessed": "2026-03-28", "owner": "SOC Team"},
    {"id": "CC7.2", "name": "System Operations - Monitoring", "category": "System Operations", "status": "Passing", "description": "Continuous monitoring of system performance and security events.", "last_assessed": "2026-03-28", "owner": "SOC Team"},
    {"id": "CC8.1", "name": "Change Management", "category": "Change Management", "status": "Failing", "description": "Change management process lacks mandatory security review gate for 15% of changes.", "last_assessed": "2026-03-05", "owner": "IT Operations"},
    {"id": "CC9.1", "name": "Risk Mitigation - Vendor Management", "category": "Risk Mitigation", "status": "In Review", "description": "Third-party vendor security assessments being expanded.", "last_assessed": "2026-02-28", "owner": "Vendor Management"},
    {"id": "A1.1", "name": "Availability - Capacity Management", "category": "Availability", "status": "Passing", "description": "Capacity monitoring and forecasting ensures system availability SLAs.", "last_assessed": "2026-03-20", "owner": "Infrastructure"},
    {"id": "C1.1", "name": "Confidentiality - Identification", "category": "Confidentiality", "status": "Passing", "description": "Confidential information identified and labeled per data classification policy.", "last_assessed": "2026-03-10", "owner": "Data Security"},
    {"id": "PI1.1", "name": "Processing Integrity", "category": "Processing Integrity", "status": "Passing", "description": "System processing integrity controls verified through automated testing.", "last_assessed": "2026-03-15", "owner": "Engineering"},
    {"id": "P1.1", "name": "Privacy - Notice and Communication", "category": "Privacy", "status": "Failing", "description": "Privacy notice requires update to reflect new data processing activities.", "last_assessed": "2026-02-15", "owner": "Legal / Privacy"},
]


def summarize_controls(framework: str, controls: list) -> dict:
    passing = sum(1 for c in controls if c["status"] == "Passing")
    failing = sum(1 for c in controls if c["status"] == "Failing")
    in_review = sum(1 for c in controls if c["status"] == "In Review")
    total = len(controls)
    score = round((passing / total) * 100, 1) if total > 0 else 0
    return {
        "framework": framework,
        "passing": passing,
        "failing": failing,
        "in_review": in_review,
        "total": total,
        "score": score,
        "controls": [{"framework": framework, **c} for c in controls],
    }


@router.get("/")
def get_compliance_overview():
    nist = summarize_controls("NIST 800-53", NIST_CONTROLS)
    soc2 = summarize_controls("SOC 2", SOC2_CONTROLS)
    all_controls = nist["controls"] + soc2["controls"]
    total = len(all_controls)
    passing = sum(1 for c in all_controls if c["status"] == "Passing")
    return {
        "overall_score": round((passing / total) * 100, 1),
        "frameworks": [nist, soc2],
    }


@router.get("/nist")
def get_nist_compliance():
    return summarize_controls("NIST 800-53", NIST_CONTROLS)


@router.get("/soc2")
def get_soc2_compliance():
    return summarize_controls("SOC 2", SOC2_CONTROLS)


@router.get("/export/csv")
def export_compliance_csv():
    all_controls = (
        [{"framework": "NIST 800-53", **c} for c in NIST_CONTROLS]
        + [{"framework": "SOC 2", **c} for c in SOC2_CONTROLS]
    )
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["framework", "id", "name", "category", "status", "description", "last_assessed", "owner"],
    )
    writer.writeheader()
    writer.writerows(all_controls)
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=compliance_export.csv"},
    )


# ── Compliance Report CRUD ───────────────────────────────────────────────────

VALID_FRAMEWORKS = {"SOC2", "HIPAA", "NIST", "CMMC"}


def _run_report_generation(report_id: int, db: Session) -> None:
    from services.compliance.report_generator import generate_report

    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not report:
        return

    try:
        from models import AlertLog, Threat

        alert_count = (
            db.query(AlertLog)
            .filter(AlertLog.created_at >= report.date_range_start)
            .filter(AlertLog.created_at <= report.date_range_end)
            .count()
        )
        threat_count = (
            db.query(Threat)
            .filter(Threat.created_at >= report.date_range_start)
            .filter(Threat.created_at <= report.date_range_end)
            .count()
        )
        report.alert_count = alert_count
        report.threat_count = threat_count
        db.commit()

        file_path = generate_report(report, db)
        report.file_path = file_path
        report.status = "ready"
        db.commit()
    except Exception as exc:
        report.status = "error"
        report.error_message = str(exc)
        db.commit()


@router.get("/reports", response_model=List[ComplianceReportOut])
def list_reports(db: Session = Depends(get_db)):
    return db.query(ComplianceReport).order_by(ComplianceReport.generated_at.desc()).all()


@router.post("/reports/generate", response_model=ComplianceReportOut, status_code=202)
def generate_compliance_report(
    payload: ComplianceReportGenerate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    if payload.framework.upper() not in VALID_FRAMEWORKS:
        raise HTTPException(status_code=400, detail=f"Invalid framework. Must be one of: {', '.join(VALID_FRAMEWORKS)}")

    if payload.date_range_start >= payload.date_range_end:
        raise HTTPException(status_code=400, detail="date_range_start must be before date_range_end")

    report = ComplianceReport(
        framework=payload.framework.upper(),
        date_range_start=payload.date_range_start,
        date_range_end=payload.date_range_end,
        generated_at=datetime.utcnow(),
        status="generating",
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    background_tasks.add_task(_run_report_generation, report.id, db)

    return report


@router.get("/reports/{report_id}", response_model=ComplianceReportOut)
def get_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "ready":
        raise HTTPException(status_code=409, detail=f"Report is not ready (status: {report.status})")
    if not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    filename = f"SentinelOps_{report.framework}_Report.pdf"
    return FileResponse(
        path=report.file_path,
        media_type="application/pdf",
        filename=filename,
    )


@router.delete("/reports/{report_id}", status_code=204)
def delete_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.file_path and os.path.exists(report.file_path):
        try:
            os.remove(report.file_path)
        except OSError:
            pass

    db.delete(report)
    db.commit()
