"""
test_reporting.py
Tests for PDF takedown dossier generation.
"""

import os
from src.reporting.report_generator import generate_report


def test_pdf_generation():
    sample_candidate = {
        "id": 999,
        "domain": "pytest-typosquat-fake.com",
        "decoded_domain": None,
        "matched_brand": "paypal.com",
        "detected_at": "2026-09-24T12:00:00Z",
        "is_live": 1,
        "ip_address": "192.0.2.1",
        "has_mx_record": 1,
        "ssl_issuer": "Let's Encrypt Authority X3",
        "visual_similarity": 0.85,
        "has_login_form": 1,
        "suspicious_phrases": "verify account",
        "risk_score": 90.0,
        "risk_level": "HIGH",
        "screenshot_path": None,
    }

    sample_whois = {
        "registrar": "Example Registrar LLC",
        "creation_date": "2026-09-20",
        "emails": ["abuse@example.com"],
        "name_servers": ["ns1.example.com"],
    }

    pdf_path = generate_report(sample_candidate, sample_whois)
    assert pdf_path is not None
    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 1000  # valid PDF size

    # Cleanup test PDF
    if os.path.exists(pdf_path):
        os.remove(pdf_path)
