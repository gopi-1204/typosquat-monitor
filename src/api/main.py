"""
main.py
FastAPI REST API for Enterprise SOC & SIEM Integration.
Provides endpoints for querying threat candidates, on-demand scanning,
triage status management, and PDF report retrieval.
"""

import os
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.storage.db import (
    init_db,
    get_all_candidates,
    get_candidate_by_id,
    update_status,
    get_metrics_summary,
    insert_candidate,
    update_liveness,
    update_screenshot_path,
    update_visual_similarity,
    update_content_signals,
    update_mail_and_ssl,
    update_risk_score,
    update_takedown_report,
)
from src.ingest.permutation_filter import get_all_monitored_brands
from src.enrichment.pipeline import analyze_domain
from src.reporting.report_generator import generate_report

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Typosquat & Brand Impersonation Threat Intelligence API",
    description="Enterprise REST interface for Certificate Transparency threat detection, composite risk scoring, and incident triage.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)




# ------------------------------------------------------------------------------
# Pydantic Request / Response Models
# ------------------------------------------------------------------------------
class StatusUpdateRequest(BaseModel):
    status: str  # 'new', 'investigating', 'takedown_requested', 'resolved', 'false_positive'
    analyst_notes: Optional[str] = None


class OnDemandScanRequest(BaseModel):
    domain: str
    matched_brand: Optional[str] = "paypal.com"
    save_to_db: Optional[bool] = True
    capture_screenshot: Optional[bool] = True


# ------------------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------------------
@app.get("/", tags=["System"])
def root():
    return {
        "status": "online",
        "service": "Typosquat & Brand Impersonation Threat Intelligence Platform",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "operational"
    }


@app.get("/api/metrics", tags=["Analytics"])
def get_metrics():
    """Returns SOC KPI metrics and aggregate candidate statistics."""
    return get_metrics_summary()


@app.get("/api/brands", tags=["Brands"])
def get_brands():
    """Returns all enterprise brands currently monitored."""
    return {"brands": get_all_monitored_brands()}


@app.get("/api/candidates", tags=["Candidates"])
def list_candidates(
    brand: Optional[str] = Query(None, description="Filter by matched brand domain"),
    risk_level: Optional[str] = Query(None, description="Filter by severity: HIGH, MEDIUM, LOW"),
    status: Optional[str] = Query(None, description="Filter by triage status: new, investigating, takedown_requested, resolved, false_positive"),
    search: Optional[str] = Query(None, description="Search keyword in domain name")
):
    """Query threat intelligence database with multi-vector filtering."""
    results = get_all_candidates(brand=brand, risk_level=risk_level, status=status, search=search)
    return {"count": len(results), "candidates": results}


@app.get("/api/candidates/{candidate_id}", tags=["Candidates"])
def get_candidate(candidate_id: int):
    """Retrieve detailed threat telemetry for a specific candidate ID."""
    candidate = get_candidate_by_id(candidate_id)
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")
    return candidate


@app.patch("/api/candidates/{candidate_id}/status", tags=["Triage"])
def update_candidate_status(candidate_id: int, req: StatusUpdateRequest):
    """Updates candidate triage status and records analyst notes."""
    valid_statuses = ["new", "investigating", "takedown_requested", "resolved", "false_positive"]
    if req.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {valid_statuses}"
        )

    existing = get_candidate_by_id(candidate_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Candidate not found")

    update_status(candidate_id, req.status, notes=req.analyst_notes)
    return {
        "success": True,
        "candidate_id": candidate_id,
        "new_status": req.status,
        "analyst_notes": req.analyst_notes
    }


@app.post("/api/scan", tags=["On-Demand Scanner"])
def scan_domain(req: OnDemandScanRequest):
    """
    On-Demand Threat Intelligence Scanner.
    Executes real-time enrichment pipeline (DNS, MX, SSL, DOM, Screenshot, pHash, Scoring).
    """
    profile = analyze_domain(
        domain=req.domain,
        matched_brand=req.matched_brand or "paypal.com",
        capture_screen=req.capture_screenshot,
        fetch_whois=True
    )

    candidate_id = None
    report_path = None

    if req.save_to_db:
        candidate_id = insert_candidate(
            domain=profile["domain"],
            matched_brand=profile["matched_brand"],
            decoded_domain=profile["decoded_domain"]
        )
        update_liveness(candidate_id, profile["is_live"], ip_address=profile["ip_address"])

        if profile["is_live"]:
            if profile["screenshot_path"]:
                update_screenshot_path(candidate_id, profile["screenshot_path"])
                update_visual_similarity(candidate_id, profile["visual_similarity"])

            update_content_signals(
                candidate_id,
                has_login_form=profile["has_login_form"],
                suspicious_phrases=profile["suspicious_phrases"]
            )
            update_mail_and_ssl(
                candidate_id,
                has_mx=profile["has_mx_record"],
                ssl_issuer=profile["ssl_issuer"]
            )

        update_risk_score(candidate_id, profile["risk_score"], profile["risk_level"])

        # Generate report for high risk
        if profile["risk_level"] == "HIGH":
            candidate_record = {
                "id": candidate_id,
                "domain": profile["domain"],
                "decoded_domain": profile["decoded_domain"],
                "matched_brand": profile["matched_brand"],
                "detected_at": "On-demand Scan",
                "is_live": profile["is_live"],
                "ip_address": profile["ip_address"],
                "has_mx_record": profile["has_mx_record"],
                "ssl_issuer": profile["ssl_issuer"],
                "visual_similarity": profile["visual_similarity"],
                "has_login_form": profile["has_login_form"],
                "suspicious_phrases": ", ".join(profile["suspicious_phrases"]),
                "risk_score": profile["risk_score"],
                "risk_level": profile["risk_level"],
                "screenshot_path": profile["screenshot_path"],
            }
            report_path = generate_report(candidate_record, profile.get("whois_info", {}))
            if report_path:
                update_takedown_report(candidate_id, report_path)

    return {
        "candidate_id": candidate_id,
        "profile": profile,
        "report_generated": bool(report_path),
        "report_path": report_path
    }


@app.get("/api/report/{candidate_id}", tags=["Reporting"])
def download_takedown_report(candidate_id: int):
    """Downloads or generates on-the-fly the PDF takedown dossier for a candidate."""
    candidate = get_candidate_by_id(candidate_id)
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    report_path = candidate.get("takedown_report_path")
    if not report_path or not os.path.exists(report_path):
        # Generate fresh report
        from src.enrichment.whois_lookup import get_whois_info
        whois_data = get_whois_info(candidate["domain"])
        report_path = generate_report(candidate, whois_data)
        if report_path:
            update_takedown_report(candidate_id, report_path)

    if not report_path or not os.path.exists(report_path):
        raise HTTPException(status_code=500, detail="Failed to generate takedown PDF")

    safe_name = os.path.basename(report_path)
    return FileResponse(
        path=report_path,
        media_type="application/pdf",
        filename=safe_name
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)
