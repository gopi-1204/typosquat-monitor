"""
test_permutation.py
Unit tests for permutation generation and brand lookalike matching.
"""

from src.ingest.permutation_filter import (
    build_permutation_set,
    is_suspicious,
    build_multi_brand_permutation_map,
    match_against_all_brands
)


def test_build_permutation_set():
    perms = build_permutation_set("paypal.com")
    assert len(perms) > 10
    # Must contain common typo variations
    assert any("paypa" in p for p in perms)


def test_own_brand_not_flagged():
    perms = build_permutation_set("paypal.com")
    assert not is_suspicious("paypal.com", perms, official_domain="paypal.com")


def test_typo_is_flagged():
    perms = build_permutation_set("paypal.com")
    # Take a known permutation from the generated set
    sample_typo = list(perms)[0]
    assert is_suspicious(sample_typo, perms, official_domain="paypal.com")


def test_combosquatting_match():
    perms = build_permutation_set("paypal.com")
    assert is_suspicious("paypal-login.com", perms, official_domain="paypal.com")


def test_multi_brand_matching():
    brand_map = build_multi_brand_permutation_map()
    assert "paypal.com" in brand_map
    assert "flipkart.com" in brand_map

    is_matched, brand, reason = match_against_all_brands("flipkart-secure-login.com", brand_map)
    assert is_matched
    assert brand == "flipkart.com"
