"""
ct_simulator.py
Real-time Certificate Transparency Stream Simulator for Live Academic Demonstrations.
Simulates realistic high-velocity certificate issuance events, interleaving benign
traffic with weaponized typosquatting, IDN homoglyphs, and combosquatting attempts.
"""

import time
import random
from src.ingest.ct_stream_client import process_threat_candidate
from src.ingest.permutation_filter import build_multi_brand_permutation_map, match_against_all_brands
from src.storage.db import init_db

BENIGN_DOMAINS = [
    "cloud-metrics.aws-east.internal",
    "portal.university-academics.edu",
    "cdn.content-delivery-network.net",
    "api.global-fintech-hub.io",
    "status.infra-telemetry.org",
    "shop.sustainable-fashion.store",
]

THREAT_CANDIDATES = [
    {"domain": "secure-flipkart-login.com", "brand": "flipkart.com", "type": "Combosquat Phishing"},
    {"domain": "paypa1-billing-update.com", "brand": "paypal.com", "type": "Typosquat / Number Substitution"},
    {"domain": "xn--pypal-4ve.com", "brand": "paypal.com", "type": "IDN Punycode Homoglyph"},
    {"domain": "auth-google-accounts.net", "brand": "google.com", "type": "SSO Credential Harvester"},
    {"domain": "github-enterprise-login.com", "brand": "github.com", "type": "Developer OAuth Impersonation"},
]


def run_simulation(interval=3, max_events=10):
    """
    Emits simulated CT stream events and routes threats to the enrichment pipeline.
    """
    init_db()
    brand_map = build_multi_brand_permutation_map()

    print("=" * 70)
    print(" 🚀 CERTIFICATE TRANSPARENCY (CT) LOG STREAM SIMULATOR")
    print("=" * 70)
    print(f"Monitoring Brands: {list(brand_map.keys())}")
    print(f"Simulating live certificate stream updates every {interval}s...\n")

    events_processed = 0

    for i in range(max_events):
        events_processed += 1
        # Interleave benign events and threat events
        is_threat = (i % 2 == 1) or (i == 0)
        
        if is_threat and THREAT_CANDIDATES:
            item = THREAT_CANDIDATES[i % len(THREAT_CANDIDATES)]
            domain = item["domain"]
            print(f"\n[CT-STREAM EVENT #{events_processed}] Ingested Certificate: CN={domain}")
            
            # Run matching
            is_match, matched_brand, reason = match_against_all_brands(domain, brand_map)
            if not matched_brand:
                matched_brand = item["brand"]
                reason = item["type"]

            print(f"  🚨 [DETECTION TRIGGERED] Matched Brand: {matched_brand} (Reason: {reason})")
            process_threat_candidate(domain, matched_brand, match_reason=reason)

        else:
            domain = random.choice(BENIGN_DOMAINS)
            print(f"[CT-STREAM EVENT #{events_processed}] Ingested Certificate: CN={domain} (Filter: PASSED - Benign)")

        time.sleep(interval)

    print("\n" + "=" * 70)
    print(" ✅ CT Log Simulation Completed. Open Streamlit Dashboard to review results.")
    print("=" * 70)


if __name__ == "__main__":
    run_simulation(interval=1.5, max_events=4)
