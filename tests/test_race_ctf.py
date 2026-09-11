from barq_crs.ctf import ChallengeTriage, FlagOracle
from barq_crs.race import StateCollisionEngine, StateTransition


def transition(route, access="write", invariant="coupon.remaining"):
    return StateTransition(route, "coupon", "redeem", access, invariant)


def test_state_collision_is_modeled():
    findings = StateCollisionEngine().analyze([transition("POST /redeem"), transition("POST /apply")])
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_unrelated_invariants_do_not_collide():
    assert StateCollisionEngine().analyze([transition("POST /a"), transition("POST /b", invariant="other")]) == []


def test_ctf_triage_prefers_forensics(tmp_path):
    (tmp_path / "capture.pcap").write_text("pcap wireshark packet memory")
    results = ChallengeTriage().analyze(tmp_path)
    assert results[0].category == "forensics"


def test_flag_oracle_deduplicates():
    assert FlagOracle().find("x flag{owned_fixture} y FLAG{owned_fixture}") == ("flag{owned_fixture}", "FLAG{owned_fixture}")


def test_flag_oracle_rejects_multiline():
    assert FlagOracle().find("flag{not\nvalid}") == ()
