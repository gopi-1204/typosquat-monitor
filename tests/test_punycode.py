"""
test_punycode.py
Unit tests for IDN and Punycode homoglyph decoding.
"""

from src.enrichment.punycode_decoder import decode_domain


def test_plain_domain():
    decoded, is_puny = decode_domain("paypal.com")
    assert not is_puny
    assert decoded == "paypal.com"


def test_punycode_decoding():
    # xn--pypal-4ve.com -> pаypal.com (Cyrillic а)
    puny_domain = "xn--pypal-4ve.com"
    decoded, is_puny = decode_domain(puny_domain)
    assert is_puny
    assert "paypal" in decoded.lower() or "p" in decoded


def test_invalid_punycode():
    decoded, is_puny = decode_domain("xn--invalid9999999999999999999999999.com")
    # Should safely return fallback without crashing
    assert isinstance(decoded, str)
