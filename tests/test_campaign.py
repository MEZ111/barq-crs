import json
from pathlib import Path

import pytest

from barq_crs.campaign import CampaignRunner
from barq_crs.cli import main
from barq_crs.collector import EvidenceCollector
from barq_crs.ledger import EvidenceLedger


ROOT = Path(__file__).resolve().parents[1]
DEMO_CAMPAIGN = ROOT / "examples" / "demo" / "hunt-campaign.json"


def test_full_campaign_emits_all_artifacts(tmp_path):
    result = CampaignRunner().run(DEMO_CAMPAIGN, tmp_path / "out")
    assert result.candidate_count >= 18
    assert result.schema_test_count >= 7
    assert result.api_sequence_count == 1
    assert result.observation_count == 3
    assert result.mobile_file_count == 3
    assert all(Path(path).is_file() for path in result.artifacts.values())


def test_campaign_ledger_is_hash_chain_verified(tmp_path):
    result = CampaignRunner().run(DEMO_CAMPAIGN, tmp_path / "out")
    valid, message = EvidenceLedger(result.artifacts["ledger"]).verify()
    assert valid is True
    assert message == f"verified {result.candidate_count + 1} entries"


def test_campaign_sarif_contains_mobile_source_locations(tmp_path):
    result = CampaignRunner().run(DEMO_CAMPAIGN, tmp_path / "out")
    sarif = json.loads(Path(result.artifacts["sarif"]).read_text())
    mobile = next(
        item
        for item in sarif["runs"][0]["results"]
        if item["properties"]["engine"] == "android-static"
        and item.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri") == "src/UnsafeWebView.java"
    )
    assert mobile["locations"][0]["physicalLocation"]["region"]["startLine"] > 0


def test_campaign_test_plan_keeps_findings_separate_from_hypotheses(tmp_path):
    result = CampaignRunner().run(DEMO_CAMPAIGN, tmp_path / "out")
    plan = json.loads(Path(result.artifacts["test_plan"]).read_text())
    candidates = json.loads(Path(result.artifacts["candidates"]).read_text())
    assert plan["schema_tests"]
    assert all("oracle" in item for item in plan["schema_tests"])
    assert all("oracle" not in item for item in candidates)


def test_repeated_run_rebuilds_instead_of_mixing_ledger_entries(tmp_path):
    output = tmp_path / "out"
    first = CampaignRunner().run(DEMO_CAMPAIGN, output)
    second = CampaignRunner().run(DEMO_CAMPAIGN, output)
    entries = EvidenceLedger(second.artifacts["ledger"]).entries()
    assert first.candidate_count == second.candidate_count
    assert len(entries) == second.candidate_count + 1


def test_campaign_rejects_input_path_escape(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    campaign_dir = tmp_path / "campaign"
    campaign_dir.mkdir()
    manifest = campaign_dir / "campaign.json"
    manifest.write_text(json.dumps({"name": "escape", "inputs": {"openapi": "../outside.json"}}))
    with pytest.raises(ValueError, match="escapes its directory"):
        CampaignRunner().run(manifest, tmp_path / "out")


def test_campaign_requires_paired_contracts(tmp_path):
    (tmp_path / "before.json").write_text("{}")
    manifest = tmp_path / "campaign.json"
    manifest.write_text(json.dumps({"inputs": {"openapi_before": "before.json"}}))
    with pytest.raises(ValueError, match="supplied together"):
        CampaignRunner().run(manifest, tmp_path / "out")


def test_campaign_requires_paired_patch_and_source(tmp_path):
    (tmp_path / "fix.diff").write_text("+if allowed():")
    manifest = tmp_path / "campaign.json"
    manifest.write_text(json.dumps({"inputs": {"security_patch": "fix.diff"}}))
    with pytest.raises(ValueError, match="supplied together"):
        CampaignRunner().run(manifest, tmp_path / "out")


def test_hunt_cli_returns_success_and_summary(tmp_path, capsys):
    result = main(["hunt", str(DEMO_CAMPAIGN), "--output", str(tmp_path / "cli")])
    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert output["campaign"] == "barq-synthetic-ground-truth"
    assert output["high_or_critical_count"] >= 1


def test_campaign_requires_non_empty_inputs(tmp_path):
    manifest = tmp_path / "campaign.json"
    manifest.write_text('{"name":"empty","inputs":{}}')
    with pytest.raises(ValueError, match="non-empty inputs"):
        CampaignRunner().run(manifest, tmp_path / "out")


def test_campaign_can_collect_bounded_live_matrix_with_injected_transport(tmp_path):
    class Response:
        status = 200
        headers = {"Content-Type": "application/json"}

        def read(self, _limit):
            return b'{"user_id":7,"email":"owned@test"}'

    class Opener:
        def open(self, _request, timeout):
            assert timeout == 2.0
            return Response()

    (tmp_path / "policy.json").write_text(
        json.dumps(
            {
                "active_testing": True,
                "targets": [
                    {
                        "pattern": "lab.example.test",
                        "methods": ["GET"],
                        "max_rps": 1,
                    }
                ],
            }
        )
    )
    (tmp_path / "requests.json").write_text(
        json.dumps(
            [
                {
                    "url": "https://lab.example.test/users/7",
                    "route": "/users/{id}",
                    "resource_id": "7",
                }
            ]
        )
    )
    (tmp_path / "profiles.json").write_text(
        json.dumps(
            [
                {"principal": "owner", "owned_resource_ids": ["7"]},
                {"principal": "reviewer", "owned_resource_ids": []},
            ]
        )
    )
    manifest = tmp_path / "campaign.json"
    manifest.write_text(
        json.dumps(
            {
                "name": "live-fixture",
                "inputs": {
                    "collection": {
                        "policy": "policy.json",
                        "requests": "requests.json",
                        "profiles": "profiles.json",
                        "limits": {"timeout_seconds": 2},
                    }
                },
            }
        )
    )
    runner = CampaignRunner(
        collector_factory=lambda policy, limits: EvidenceCollector(
            policy,
            limits,
            opener=Opener(),
            clock=lambda: 0,
            sleeper=lambda _seconds: None,
        )
    )
    result = runner.run(manifest, tmp_path / "out")
    assert result.observation_count == 2
    assert any(item["title"] == "Non-owner received protected object data" for item in result.top_candidates)
