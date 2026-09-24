"""
ct_stream_client.py
Asynchronous, high-throughput CT stream client.
Ingests Certificate Transparency (CT) log updates over WebSockets, filters against
monitored brand lookalikes, and delegates enrichment to a non-blocking worker pool.
"""

import argparse
import json
import os
import websocket
from concurrent.futures import ThreadPoolExecutor

from src.ingest.permutation_filter import (
    get_brand_settings,
    build_permutation_set,
    build_multi_brand_permutation_map,
    is_suspicious,
    match_against_all_brands
)
from src.storage.db import (
    init_db, insert_candidate, update_liveness,
    update_screenshot_path, update_visual_similarity,
    update_content_signals, update_mail_and_ssl,
    update_risk_score, update_takedown_report
)
from src.enrichment.pipeline import analyze_domain
from src.enrichment.screenshot import ensure_reference_screenshot
from src.alerts.telegram_bot import send_alert
from src.reporting.report_generator import generate_report

DEFAULT_CERTSTREAM_URL = os.getenv("CERTSTREAM_URL", "ws://localhost:8081/full-stream")
WORKER_POOL = ThreadPoolExecutor(max_workers=5, thread_name_prefix="threat-enricher")


def process_threat_candidate(domain, matched_brand, match_reason="lookalike"):
    """
    Worker task: runs full multi-signal enrichment, risk scoring, alerting,
    and takedown report generation without blocking CT stream ingestion.
    """
    print(f"\n[WORKER] Enriching candidate: {domain} (Brand: {matched_brand}, Reason: {match_reason})")
    try:
        # Run unified multi-vector enrichment pipeline
        profile = analyze_domain(
            domain,
            matched_brand=matched_brand,
            capture_screen=True,
            fetch_whois=True
        )

        candidate_id = insert_candidate(
            domain=domain,
            matched_brand=matched_brand,
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
        print(f"[WORKER RESULT] {domain} -> Risk Score: {profile['risk_score']}/100 ({profile['risk_level']})")

        # High risk incident response triggers
        if profile["risk_level"] == "HIGH":
            send_alert(domain, profile["risk_score"], profile["risk_level"], matched_brand)
            candidate_record = {
                "id": candidate_id,
                "domain": domain,
                "decoded_domain": profile["decoded_domain"],
                "matched_brand": matched_brand,
                "detected_at": "CT Stream Live",
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
                print(f"[WORKER DOSSIER] Takedown report generated: {report_path}")

    except Exception as e:
        print(f"[WORKER ERROR] Enrichment failed for {domain}: {e}")


def on_message(ws, message, brand_map, single_brand=None, single_perms=None):
    """Non-blocking message handler: evaluates domains and submits matches to worker pool."""
    try:
        data = json.loads(message)
        if data.get("message_type") != "certificate_update":
            return

        leaf_cert = data.get("data", {}).get("leaf_cert", {})
        domains = leaf_cert.get("all_domains", [])

        for domain in domains:
            domain = domain.lower().lstrip("*.")

            if single_brand and single_perms:
                if is_suspicious(domain, single_perms, official_domain=single_brand):
                    print(f"[STREAM MATCH] Flagged: {domain} -> Impersonating: {single_brand}")
                    WORKER_POOL.submit(process_threat_candidate, domain, single_brand, "single_brand_match")
            else:
                is_match, matched_brand, reason = match_against_all_brands(domain, brand_map)
                if is_match:
                    print(f"[STREAM MATCH] Flagged: {domain} -> Impersonating: {matched_brand} ({reason})")
                    WORKER_POOL.submit(process_threat_candidate, domain, matched_brand, reason)

    except Exception as e:
        print(f"Error handling CT message: {e}")


def on_error(ws, error):
    print(f"[STREAM ERROR] {error}")


def on_close(ws, close_status_code, close_msg):
    print("[STREAM CLOSED] Connection terminated.")


def on_open(ws):
    print(">>> Connected to Certificate Transparency WebSocket stream.")
    print(">>> Threat monitoring engine is active and non-blocking.\n")


def run_monitor(brand_override=None, server_url=DEFAULT_CERTSTREAM_URL):
    init_db()

    single_brand = None
    single_perms = None
    brand_map = None

    if brand_override:
        single_brand = get_brand_settings(cli_brand=brand_override)
        single_perms = build_permutation_set(single_brand)
        ensure_reference_screenshot(single_brand)
        print(f"Monitoring targeted brand: {single_brand} ({len(single_perms)} lookalike permutations)")
    else:
        brand_map = build_multi_brand_permutation_map()
        for b_domain in brand_map.keys():
            ensure_reference_screenshot(b_domain)
        print(f"Enterprise Multi-Brand Mode: Watching {len(brand_map)} brands: {list(brand_map.keys())}")

    ws = websocket.WebSocketApp(
        server_url,
        on_open=on_open,
        on_message=lambda ws, msg: on_message(ws, msg, brand_map, single_brand, single_perms),
        on_error=on_error,
        on_close=on_close,
    )
    ws.run_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CT Stream Typosquat Threat Monitor")
    parser.add_argument("--brand", help="Override brand domain, e.g. flipkart.com")
    parser.add_argument("--server", default=DEFAULT_CERTSTREAM_URL, help="CertStream WebSocket URL")
    args = parser.parse_args()

    run_monitor(brand_override=args.brand, server_url=args.server)
