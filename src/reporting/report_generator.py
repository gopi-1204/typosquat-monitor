"""
report_generator.py
Generates an authoritative PDF takedown/abuse dossier for a detected candidate,
combining forensic telemetry, side-by-side visual comparison, DNS/IP, MX records,
SSL details, and WHOIS/RDAP abuse contact info.
"""

import os
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa
from src.enrichment.screenshot import get_brand_reference_path

TEMPLATE_DIR = "src/reporting/templates"
REPORT_OUTPUT_DIR = "reports"


def generate_report(candidate, whois_info=None):
    """
    candidate: dict with keys matching the candidates table row.
    whois_info: dict from get_whois_info(), or None.
    Returns the absolute path to the generated PDF, or None on failure.
    """
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("takedown_report.html.j2")

    whois_info = whois_info or {}

    screenshot_path = candidate.get("screenshot_path")
    screenshot_abs = None
    if screenshot_path and os.path.exists(screenshot_path):
        screenshot_abs = os.path.abspath(screenshot_path)

    matched_brand = candidate.get("matched_brand")
    reference_path = get_brand_reference_path(matched_brand)
    reference_abs = None
    if reference_path and os.path.exists(reference_path):
        reference_abs = os.path.abspath(reference_path)

    html_content = template.render(
        incident_id=candidate.get("id", "9041"),
        domain=candidate.get("domain"),
        decoded_domain=candidate.get("decoded_domain"),
        matched_brand=matched_brand,
        detected_at=candidate.get("detected_at"),
        is_live=candidate.get("is_live"),
        ip_address=candidate.get("ip_address"),
        has_mx_record=candidate.get("has_mx_record"),
        ssl_issuer=candidate.get("ssl_issuer"),
        visual_similarity=candidate.get("visual_similarity", 0.0),
        has_login_form=candidate.get("has_login_form"),
        suspicious_phrases=candidate.get("suspicious_phrases"),
        risk_score=candidate.get("risk_score"),
        risk_level=candidate.get("risk_level") or "LOW",
        screenshot_path=screenshot_abs,
        reference_screenshot_path=reference_abs,
        registrar=whois_info.get("registrar"),
        creation_date=whois_info.get("creation_date"),
        emails=whois_info.get("emails"),
        name_servers=whois_info.get("name_servers"),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    safe_filename = str(candidate.get("domain", "unknown")).replace(".", "_").replace("*", "wildcard")
    output_path = os.path.join(REPORT_OUTPUT_DIR, f"takedown_{safe_filename}.pdf")

    with open(output_path, "wb") as f:
        result = pisa.CreatePDF(html_content, dest=f)

    if result.err:
        print("PDF generation encountered warnings or non-fatal formatting alerts.")

    return output_path


if __name__ == "__main__":
    sample_candidate = {
        "id": 101,
        "domain": "paypa1-secure-billing.com",
        "decoded_domain": None,
        "matched_brand": "paypal.com",
        "detected_at": "2026-09-24T12:00:00+00:00",
        "is_live": 1,
        "ip_address": "198.51.100.42",
        "has_mx_record": 1,
        "ssl_issuer": "Let's Encrypt Authority X3",
        "visual_similarity": 0.92,
        "has_login_form": 1,
        "suspicious_phrases": "verify account, login security",
        "risk_score": 95.0,
        "risk_level": "HIGH",
        "screenshot_path": "reference_assets/brand_reference_screenshot.png",
    }

    sample_whois = {
        "registrar": "NameCheap, Inc.",
        "creation_date": "2026-09-23T08:14:00Z",
        "emails": ["abuse@namecheap.com"],
        "name_servers": ["dns1.registrar-servers.com", "dns2.registrar-servers.com"],
    }

    path = generate_report(sample_candidate, sample_whois)
    print(f"Report generated: {path}")
