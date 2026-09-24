"""
seed_data.py
Populates SQLite database with rich, realistic enterprise threat intelligence records
spanning multiple brands (Flipkart, PayPal, Google, GitHub), severity tiers, and incident statuses.
Ideal for demo presentations, viva defense, and UI testing.
"""

from datetime import datetime, timedelta, timezone
from src.storage.db import (
    init_db,
    insert_candidate,
    update_liveness,
    update_screenshot_path,
    update_visual_similarity,
    update_content_signals,
    update_mail_and_ssl,
    update_risk_score,
    update_status,
    update_takedown_report,
)
from src.scoring.risk_score import compute_risk_score, risk_level
from src.reporting.report_generator import generate_report

SEEDED_THREATS = [
    {
        "domain": "flipkart-secure-login.com",
        "decoded_domain": None,
        "matched_brand": "flipkart.com",
        "is_live": True,
        "ip_address": "104.21.64.120",
        "has_mx": True,
        "ssl_issuer": "Let's Encrypt Authority X3",
        "visual_sim": 0.94,
        "has_login": True,
        "phrases": ["verify your account", "confirm identity"],
        "status": "takedown_requested",
        "notes": "Confirmed credential harvester impersonating Flipkart login portal. Registrar abuse ticket #FK-901 dispatched.",
        "days_ago": 1,
        "screenshot": "reference_assets/brand_reference_screenshot.png"
    },
    {
        "domain": "paypa1-secure-billing.com",
        "decoded_domain": None,
        "matched_brand": "paypal.com",
        "is_live": True,
        "ip_address": "198.51.100.88",
        "has_mx": True,
        "ssl_issuer": "ZeroSSL Domain Validation",
        "visual_sim": 0.88,
        "has_login": True,
        "phrases": ["your account has been locked", "update your payment"],
        "status": "investigating",
        "notes": "Phishing lure targeting PayPal business accounts. Active MX records point to burner mail server.",
        "days_ago": 2,
        "screenshot": "reference_assets/brand_reference_screenshot.png"
    },
    {
        "domain": "xn--pypal-4ve.com",
        "decoded_domain": "pаypal.com",
        "matched_brand": "paypal.com",
        "is_live": True,
        "ip_address": "172.67.182.204",
        "has_mx": False,
        "ssl_issuer": "Cloudflare Origin CA",
        "visual_sim": 0.91,
        "has_login": True,
        "phrases": ["unusual activity", "verify your account"],
        "status": "new",
        "notes": "Cyrillic homoglyph confusable (Cyrillic 'а' replacing Latin 'a'). High risk IDN spoofing.",
        "days_ago": 0,
        "screenshot": "reference_assets/brand_reference_screenshot.png"
    },
    {
        "domain": "auth-google-accounts.net",
        "decoded_domain": None,
        "matched_brand": "google.com",
        "is_live": True,
        "ip_address": "142.250.190.46",
        "has_mx": True,
        "ssl_issuer": "Google Trust Services",
        "visual_sim": 0.72,
        "has_login": True,
        "phrases": ["click here to verify"],
        "status": "resolved",
        "notes": "Domain suspended by registrar following abuse report submission.",
        "days_ago": 4,
        "screenshot": "data/screenshots/google_com.png"
    },
    {
        "domain": "github-enterprise-auth.org",
        "decoded_domain": None,
        "matched_brand": "github.com",
        "is_live": True,
        "ip_address": "140.82.121.4",
        "has_mx": False,
        "ssl_issuer": "Let's Encrypt Authority X3",
        "visual_sim": 0.65,
        "has_login": True,
        "phrases": ["verify your identity"],
        "status": "investigating",
        "notes": "Combosquat domain targeting developer OAuth credentials.",
        "days_ago": 3,
        "screenshot": "data/screenshots/github_com.png"
    },
    {
        "domain": "flipkarrt-offers.in",
        "decoded_domain": None,
        "matched_brand": "flipkart.com",
        "is_live": True,
        "ip_address": "185.199.108.153",
        "has_mx": False,
        "ssl_issuer": "cPanel, Inc. Certification Authority",
        "visual_sim": 0.35,
        "has_login": False,
        "phrases": [],
        "status": "new",
        "notes": "Repetition typosquatting. Parked parking page with affiliate advertisements.",
        "days_ago": 5,
        "screenshot": "data/screenshots/flipkart_com.png"
    },
    {
        "domain": "paypaal.org",
        "decoded_domain": None,
        "matched_brand": "paypal.com",
        "is_live": False,
        "ip_address": None,
        "has_mx": False,
        "ssl_issuer": None,
        "visual_sim": 0.0,
        "has_login": False,
        "phrases": [],
        "status": "new",
        "notes": "Unresolved lookalike domain registered defensively or currently dormant.",
        "days_ago": 6,
        "screenshot": None
    },
    {
        "domain": "python-docs-archive.org",
        "decoded_domain": None,
        "matched_brand": "python.org",
        "is_live": True,
        "ip_address": "151.101.0.223",
        "has_mx": False,
        "ssl_issuer": "Let's Encrypt Authority X3",
        "visual_sim": 0.22,
        "has_login": False,
        "phrases": [],
        "status": "false_positive",
        "notes": "Legitimate community documentation mirror. Marked as false positive.",
        "days_ago": 7,
        "screenshot": "data/screenshots/python_org.png"
    }
]


def seed_database():
    init_db()
    print("Seeding threat intelligence database...")

    for item in SEEDED_THREATS:
        cid = insert_candidate(
            domain=item["domain"],
            matched_brand=item["matched_brand"],
            decoded_domain=item["decoded_domain"]
        )

        update_liveness(cid, item["is_live"], ip_address=item["ip_address"])

        if item["screenshot"]:
            update_screenshot_path(cid, item["screenshot"])
            update_visual_similarity(cid, item["visual_sim"])

        update_content_signals(
            cid,
            has_login_form=item["has_login"],
            suspicious_phrases=item["phrases"]
        )

        update_mail_and_ssl(
            cid,
            has_mx=item["has_mx"],
            ssl_issuer=item["ssl_issuer"]
        )

        score, breakdown = compute_risk_score(
            is_live=item["is_live"],
            visual_similarity=item["visual_sim"],
            has_login_form=item["has_login"],
            suspicious_phrase_count=len(item["phrases"]),
            has_mx_record=item["has_mx"],
            suspicious_ssl=bool(item["ssl_issuer"])
        )
        lvl = risk_level(score)
        update_risk_score(cid, score, lvl)

        update_status(cid, item["status"], notes=item["notes"])

        # Generate report for high risk
        if lvl == "HIGH":
            candidate_record = {
                "id": cid,
                "domain": item["domain"],
                "decoded_domain": item["decoded_domain"],
                "matched_brand": item["matched_brand"],
                "detected_at": (datetime.now(timezone.utc) - timedelta(days=item["days_ago"])).isoformat(),
                "is_live": item["is_live"],
                "ip_address": item["ip_address"],
                "has_mx_record": item["has_mx"],
                "ssl_issuer": item["ssl_issuer"],
                "visual_similarity": item["visual_sim"],
                "has_login_form": item["has_login"],
                "suspicious_phrases": ", ".join(item["phrases"]),
                "risk_score": score,
                "risk_level": lvl,
                "screenshot_path": item["screenshot"],
            }
            sample_whois = {
                "registrar": "NameCheap / Cloudflare / GoDaddy",
                "creation_date": "2026-09-20",
                "emails": ["abuse-report@registrar-compliance.net"],
                "name_servers": ["ns1.hostnameserver.com", "ns2.hostnameserver.com"],
            }
            report_path = generate_report(candidate_record, sample_whois)
            if report_path:
                update_takedown_report(cid, report_path)

        print(f" -> Added: {item['domain']:32s} | Brand: {item['matched_brand']:12s} | Risk: {score:5.1f} ({lvl:6s}) | Status: {item['status']}")

    print("\n✅ Database successfully seeded with diverse realistic threat records!")


if __name__ == "__main__":
    seed_database()
