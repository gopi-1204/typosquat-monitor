"""
permutation_filter.py
Generates typosquat/homoglyph permutations for target brands using dnstwist,
combosquat heuristics, and checks whether an incoming domain matches any of them.
Supports single-brand and multi-brand enterprise monitoring.
"""

import argparse
import yaml
import dnstwist


def load_brand_config(config_path="config/brand_config.yaml"):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def get_brand_settings(cli_brand=None, config_path="config/brand_config.yaml"):
    config = load_brand_config(config_path)

    if cli_brand:
        official_domain = cli_brand
    else:
        official_domain = config.get("official_domain", "paypal.com")

    return official_domain


def get_all_monitored_brands(config_path="config/brand_config.yaml"):
    """
    Returns a list of dicts for all monitored brands configured in YAML.
    Falls back to single brand if 'brands' list is not present.
    """
    config = load_brand_config(config_path)
    if "brands" in config and isinstance(config["brands"], list):
        return config["brands"]
    
    # Fallback to single brand format
    return [{
        "brand_name": config.get("brand_name", "paypal"),
        "official_domain": config.get("official_domain", "paypal.com"),
        "similarity_threshold": config.get("similarity_threshold", 0.8),
        "keywords": ["login", "verify", "secure", "account"]
    }]


def build_permutation_set(official_domain):
    """Generates dnstwist algorithmic permutations for an official domain."""
    fuzzer = dnstwist.Fuzzer(official_domain)
    fuzzer.generate()

    permutations = set()
    for entry in fuzzer.permutations():
        permutations.add(entry["domain"].lower())

    return permutations


def build_multi_brand_permutation_map(config_path="config/brand_config.yaml"):
    """
    Precomputes permutation sets and brand metadata for all configured brands.
    Returns: { official_domain: {"name": brand_name, "permutations": set, "keywords": list} }
    """
    brands = get_all_monitored_brands(config_path)
    brand_map = {}

    for brand in brands:
        domain = brand["official_domain"].lower()
        brand_map[domain] = {
            "name": brand.get("brand_name", domain.split(".")[0]),
            "official_domain": domain,
            "permutations": build_permutation_set(domain),
            "keywords": brand.get("keywords", ["login", "verify", "secure", "account"]),
            "threshold": brand.get("similarity_threshold", 0.8)
        }

    return brand_map


def is_suspicious(domain, permutation_set, official_domain=None):
    """
    Single-brand check: checks if domain matches dnstwist permutation set
    or combosquatting pattern on official domain name.
    """
    domain = domain.lower().lstrip("*.")
    if official_domain and domain == official_domain.lower():
        return False  # never flag the brand's own real domain
    
    # Exact match in permutation set (homoglyph, insertion, transposition, etc.)
    if domain in permutation_set:
        return True

    # Combosquatting / hyphenation heuristic check (e.g. flipkart-secure-login.com)
    if official_domain:
        brand_core = official_domain.split(".")[0].lower()
        if brand_core in domain and domain != official_domain.lower():
            # Check for phishing/impersonation markers
            suspicious_markers = ["login", "secure", "verify", "account", "update", "support", "auth", "billing"]
            if any(marker in domain for marker in suspicious_markers):
                return True

    return False


def match_against_all_brands(domain, brand_map):
    """
    Matches candidate domain against multi-brand dictionary.
    Returns: (is_matched: bool, matched_brand: str or None, reason: str or None)
    """
    clean_domain = domain.lower().lstrip("*.")

    for official_domain, data in brand_map.items():
        if clean_domain == official_domain:
            continue  # Legitimate official domain

        # 1. Direct permutation check
        if clean_domain in data["permutations"]:
            return True, official_domain, "dnstwist_permutation"

        # 2. Combosquatting heuristic (brand name + security/auth keywords)
        brand_core = official_domain.split(".")[0]
        if brand_core in clean_domain:
            for kw in data["keywords"] + ["login", "secure", "verify", "account", "auth"]:
                if kw in clean_domain:
                    return True, official_domain, f"combosquatting_{kw}"

    return False, None, None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--brand", help="Override brand domain, e.g. flipkart.com")
    args = parser.parse_args()

    official_domain = get_brand_settings(cli_brand=args.brand)
    perms = build_permutation_set(official_domain)

    print(f"Brand: {official_domain}")
    print(f"Generated {len(perms)} permutations. Sample:")
    for p in list(perms)[:15]:
        print(f"  {p}")
