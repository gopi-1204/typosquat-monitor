"""
pipeline.py
Unified Threat Enrichment & Analysis Pipeline.
Orchestrates multi-vector signals (IDN, DNS, MX, SSL, DOM, Playwright, pHash, WHOIS)
into a comprehensive threat intelligence dossier.
"""

from src.enrichment.punycode_decoder import decode_domain
from src.enrichment.dns_check import resolve_domain_ip
from src.enrichment.mail_check import check_mx_records
from src.enrichment.ssl_check import inspect_ssl_certificate
from src.enrichment.screenshot import capture_screenshot, get_brand_reference_path
from src.enrichment.visual_similarity import compute_similarity
from src.enrichment.content_signals import fetch_page_html, analyze_content
from src.enrichment.whois_lookup import get_whois_info
from src.scoring.risk_score import compute_risk_score, risk_level


def analyze_domain(domain, matched_brand="paypal.com", capture_screen=True, fetch_whois=True):
    """
    Executes end-to-end enrichment pipeline for an arbitrary candidate domain.
    Returns:
        dict: Full threat profile with all signals, raw breakdown, and risk metrics.
    """
    domain = domain.strip().lower().lstrip("*.")

    # 1. Punycode / IDN Homoglyph Decoding
    decoded_domain, is_punycode = decode_domain(domain)

    # 2. DNS Resolution & IP
    is_live, ip_address = resolve_domain_ip(domain)

    # 3. Mail Server (MX) Infrastructure
    mail_info = check_mx_records(domain)
    has_mx = mail_info.get("has_mx", False)

    # 4. SSL/TLS Inspection
    ssl_info = {"has_ssl": False, "issuer": "None", "is_free_dv": False}
    if is_live:
        ssl_info = inspect_ssl_certificate(domain)

    # 5. Screenshot & Visual Similarity
    screenshot_path = None
    visual_similarity = 0.0
    if is_live and capture_screen:
        screenshot_path = capture_screenshot(domain)
        if screenshot_path:
            visual_similarity = compute_similarity(
                screenshot_path,
                brand_domain=matched_brand
            )

    # 6. DOM & Phishing Content Signals
    has_login_form = False
    has_password_field = False
    suspicious_phrases = []
    if is_live:
        html = fetch_page_html(domain)
        if html:
            content_res = analyze_content(html)
            has_login_form = content_res.get("has_login_form", False)
            has_password_field = content_res.get("has_password_field", False)
            suspicious_phrases = content_res.get("suspicious_phrases_found", [])

    # 7. Composite Risk Scoring
    score, breakdown = compute_risk_score(
        is_live=is_live,
        visual_similarity=visual_similarity,
        has_login_form=has_login_form,
        suspicious_phrase_count=len(suspicious_phrases),
        has_mx_record=has_mx,
        suspicious_ssl=ssl_info.get("is_free_dv", False)
    )
    level = risk_level(score)

    # 8. WHOIS / RDAP Information
    whois_info = {}
    if fetch_whois:
        whois_info = get_whois_info(domain)

    return {
        "domain": domain,
        "decoded_domain": decoded_domain if is_punycode else None,
        "is_punycode": is_punycode,
        "matched_brand": matched_brand,
        "is_live": is_live,
        "ip_address": ip_address,
        "has_mx_record": has_mx,
        "mx_hosts": mail_info.get("mx_hosts", []),
        "ssl_has_cert": ssl_info.get("has_ssl", False),
        "ssl_issuer": ssl_info.get("issuer", "None"),
        "ssl_is_free_dv": ssl_info.get("is_free_dv", False),
        "screenshot_path": screenshot_path,
        "reference_screenshot_path": get_brand_reference_path(matched_brand),
        "visual_similarity": visual_similarity,
        "has_login_form": has_login_form,
        "has_password_field": has_password_field,
        "suspicious_phrases": suspicious_phrases,
        "risk_score": score,
        "risk_level": level,
        "score_breakdown": breakdown,
        "whois_info": whois_info
    }


if __name__ == "__main__":
    profile = analyze_domain("flipkart-secure-login.com", matched_brand="flipkart.com", capture_screen=False, fetch_whois=False)
    print("Enrichment Profile Output:")
    for k, v in profile.items():
        print(f"  {k}: {v}")
