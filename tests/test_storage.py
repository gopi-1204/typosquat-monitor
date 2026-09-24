"""
test_storage.py
Unit tests for database models, migrations, and CRUD operations.
"""

from src.storage.db import (
    init_db,
    insert_candidate,
    update_liveness,
    update_risk_score,
    update_status,
    get_candidate_by_id,
    get_all_candidates,
    get_metrics_summary,
    delete_candidate
)


def test_db_lifecycle():
    init_db()

    # 1. Insert
    cid = insert_candidate("test-domain-sample.com", "paypal.com")
    assert cid is not None
    assert cid > 0

    # 2. Update
    update_liveness(cid, True, ip_address="192.0.2.1")
    update_risk_score(cid, 85.0, "HIGH")
    update_status(cid, "investigating", notes="Test analyst note")

    # 3. Retrieve
    item = get_candidate_by_id(cid)
    assert item is not None
    assert item["domain"] == "test-domain-sample.com"
    assert item["matched_brand"] == "paypal.com"
    assert item["risk_score"] == 85.0
    assert item["risk_level"] == "HIGH"
    assert item["status"] == "investigating"
    assert item["analyst_notes"] == "Test analyst note"

    # 4. Filter
    filtered = get_all_candidates(brand="paypal.com", risk_level="HIGH")
    assert any(c["id"] == cid for c in filtered)

    # 5. Metrics
    metrics = get_metrics_summary()
    assert metrics["total"] > 0

    # 6. Cleanup
    delete_candidate(cid)
    assert get_candidate_by_id(cid) is None
