"""
Unit tests for the dnstwist-based typosquat permutation filter.
"""

import pytest
from src.ingest.permutation_filter import build_permutation_set, is_suspicious


@pytest.fixture(scope="module")
def flipkart_permutations():
    return build_permutation_set("flipkart.com")


def test_known_typosquat_is_flagged(flipkart_permutations):
    assert is_suspicious("flipkaret.com", flipkart_permutations, official_domain="flipkart.com") is True


def test_unrelated_domain_not_flagged(flipkart_permutations):
    assert is_suspicious("google.com", flipkart_permutations, official_domain="flipkart.com") is False


def test_official_domain_never_flags_itself(flipkart_permutations):
    assert is_suspicious("flipkart.com", flipkart_permutations, official_domain="flipkart.com") is False


def test_wildcard_prefix_is_stripped(flipkart_permutations):
    assert is_suspicious("*.flipkaret.com", flipkart_permutations, official_domain="flipkart.com") is True


def test_permutation_set_is_nonempty(flipkart_permutations):
    assert len(flipkart_permutations) > 1000
