"""
risk_score.py
Combines multi-vector enrichment signals into a weighted composite threat score (0-100).
Evaluates DNS liveness, computer vision similarity (pHash), credential harvesting forms,
suspicious phishing phrases, MX mail infrastructure, and SSL certificate telemetry.
"""

WEIGHTS = {
    "is_live": 20,
    "visual_similarity": 30,
    "has_login_form": 20,
    "suspicious_phrases": 10,
    "has_mx_record": 10,
    "suspicious_ssl": 10,
}


def compute_risk_score(
    is_live,
    visual_similarity=0.0,
    has_login_form=False,
    suspicious_phrase_count=0,
    has_mx_record=False,
    suspicious_ssl=False
):
    """
    Computes composite risk score (0-100) and returns (total_score, breakdown_dict).
    Supports 4-argument legacy signature and 6-argument full multi-vector signature.
    """
    breakdown = {}

    # 1. DNS Liveness (20 pts)
    live_score = WEIGHTS["is_live"] if is_live else 0
    breakdown["is_live"] = live_score

    # 2. Visual Similarity (30 pts)
    sim_val = float(visual_similarity or 0.0)
    sim_score = min(max(sim_val, 0.0), 1.0) * WEIGHTS["visual_similarity"]
    breakdown["visual_similarity"] = round(sim_score, 2)

    # 3. Login / Credential Harvest Form (20 pts)
    login_score = WEIGHTS["has_login_form"] if has_login_form else 0
    breakdown["has_login_form"] = login_score

    # 4. Phishing Phrases (10 pts)
    phrase_score = (min(suspicious_phrase_count, 3) / 3) * WEIGHTS["suspicious_phrases"]
    breakdown["suspicious_phrases"] = round(phrase_score, 2)

    # 5. MX Mail Exchanger Infrastructure (10 pts)
    mx_score = WEIGHTS["has_mx_record"] if has_mx_record else 0
    breakdown["has_mx_record"] = mx_score

    # 6. SSL Telemetry (10 pts)
    ssl_score = WEIGHTS["suspicious_ssl"] if suspicious_ssl else 0
    breakdown["suspicious_ssl"] = ssl_score

    total = sum(breakdown.values())
    total = round(min(max(total, 0.0), 100.0), 2)

    return total, breakdown


def risk_level(score):
    """
    Maps numerical score (0-100) to SOC threat severity level.
    """
    if score >= 70:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    else:
        return "LOW"


def explain_scoring_formula():
    """
    Returns markdown explanation of the scoring algorithm for viva / presentation defense.
    """
    return """
### Composite Threat Scoring Formula (0 - 100)
$$Score = W_{DNS} + W_{Visual} + W_{Login} + W_{Phrases} + W_{MX} + W_{SSL}$$

| Signal Vector | Weight | Evaluation Criteria |
| :--- | :---: | :--- |
| **DNS Resolution** | **20 pts** | Domain actively resolves to IPv4/IPv6 host. |
| **Visual Similarity** | **30 pts** | Perceptual hash distance ($1 - \\frac{d_{pHash}}{64}$) vs brand reference. |
| **Credential Harvesting** | **20 pts** | Form containing `<input type="password">` detected in DOM. |
| **Phishing Keywords** | **10 pts** | Scaled match of high-confidence lures (e.g. *verify account*, *unusual activity*). |
| **Email Infrastructure** | **10 pts** | Active MX / Mail records present (spear-phishing vector). |
| **SSL Telemetry** | **10 pts** | Short-lived / automated Domain Validation (DV) certificate detected. |
"""


if __name__ == "__main__":
    test_cases = [
        {
            "name": "Weaponized Phishing Portal (Flipkart lookalike)",
            "is_live": True,
            "visual_similarity": 0.95,
            "has_login_form": True,
            "suspicious_phrase_count": 2,
            "has_mx_record": True,
            "suspicious_ssl": True
        },
        {
            "name": "Parked / Dead Domain",
            "is_live": False,
            "visual_similarity": 0.0,
            "has_login_form": False,
            "suspicious_phrase_count": 0,
            "has_mx_record": False,
            "suspicious_ssl": False
        },
        {
            "name": "Benign Live Site (e.g. github.com)",
            "is_live": True,
            "visual_similarity": 0.35,
            "has_login_form": False,
            "suspicious_phrase_count": 0,
            "has_mx_record": True,
            "suspicious_ssl": False
        }
    ]

    for case in test_cases:
        score, breakdown = compute_risk_score(
            is_live=case["is_live"],
            visual_similarity=case["visual_similarity"],
            has_login_form=case["has_login_form"],
            suspicious_phrase_count=case["suspicious_phrase_count"],
            has_mx_record=case["has_mx_record"],
            suspicious_ssl=case["suspicious_ssl"]
        )
        lvl = risk_level(score)
        print(f"\n{case['name']}")
        print(f"  Score: {score}/100 ({lvl})")
        print(f"  Breakdown: {breakdown}")
