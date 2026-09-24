"""
test_scoring.py
Unit tests for the Composite Risk Scoring Engine.
"""

import pytest
from src.scoring.risk_score import compute_risk_score, risk_level, WEIGHTS


def test_weights_sum_to_100():
    total_weight = sum(WEIGHTS.values())
    assert total_weight == 100, f"Total weight must sum to 100, got {total_weight}"


def test_max_score_is_100():
    score, breakdown = compute_risk_score(
        is_live=True,
        visual_similarity=1.0,
        has_login_form=True,
        suspicious_phrase_count=5,
        has_mx_record=True,
        suspicious_ssl=True
    )
    assert score == 100.0
    assert risk_level(score) == "HIGH"


def test_zero_score_for_dormant():
    score, breakdown = compute_risk_score(
        is_live=False,
        visual_similarity=0.0,
        has_login_form=False,
        suspicious_phrase_count=0,
        has_mx_record=False,
        suspicious_ssl=False
    )
    assert score == 0.0
    assert risk_level(score) == "LOW"


def test_risk_level_thresholds():
    assert risk_level(70.0) == "HIGH"
    assert risk_level(85.5) == "HIGH"
    assert risk_level(69.9) == "MEDIUM"
    assert risk_level(50.0) == "MEDIUM"
    assert risk_level(49.9) == "LOW"
    assert risk_level(0.0) == "LOW"


def test_partial_weights():
    score, breakdown = compute_risk_score(
        is_live=True,
        visual_similarity=0.5,
        has_login_form=False,
        suspicious_phrase_count=0,
        has_mx_record=False,
        suspicious_ssl=False
    )
    expected = 20.0 + (0.5 * 30.0)
    assert score == expected
    assert breakdown["is_live"] == 20
    assert breakdown["visual_similarity"] == 15.0
