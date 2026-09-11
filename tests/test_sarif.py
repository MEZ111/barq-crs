from barq_crs.models import Candidate, Evidence
from barq_crs.sarif import sarif_report


def candidate(target="module.py:42::read_user"):
    return Candidate("variant", "missing-guard", "Missing guard", target, "high", .8, .9, .9, 1,
                     (Evidence("ast", "match", "abc"),), "add guard", "review locally")


def test_sarif_has_source_location_and_fingerprint():
    report = sarif_report([candidate()])
    result = report["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 42
    assert result["partialFingerprints"]["barqCandidateId"].startswith("barq-")


def test_sarif_omits_fake_location_for_route_target():
    result = sarif_report([candidate("GET /v1/account")])["runs"][0]["results"][0]
    assert "locations" not in result


def test_sarif_deduplicates_rules():
    report = sarif_report([candidate(), candidate("other.py:2::x")])
    assert len(report["runs"][0]["tool"]["driver"]["rules"]) == 1
