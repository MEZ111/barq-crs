import json

from barq_crs.ledger import EvidenceLedger


def test_hash_chain_and_redaction(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger(path)
    ledger.append("observation", "2026-09-11T00:00:00Z", {"Authorization": "Bearer secret", "status": 200})
    ledger.append("finding", "2026-09-11T00:00:01Z", {"id": "barq-1"})
    assert ledger.verify() == (True, "verified 2 entries")
    assert "Bearer secret" not in path.read_text()


def test_tamper_is_detected(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger(path)
    ledger.append("finding", "now", {"status": 200})
    value = json.loads(path.read_text())
    value["payload"]["status"] = 500
    path.write_text(json.dumps(value) + "\n")
    assert ledger.verify()[0] is False
