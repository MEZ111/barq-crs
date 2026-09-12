from __future__ import annotations

import json
from pathlib import Path

import pytest

from barq_crs.bounty import BountyError, BountyRunner, EndpointPrioritizer


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _policy(path: Path, *, include_wildcard: bool = True) -> None:
    targets = [
        {
            "pattern": "example.com",
            "schemes": ["https"],
            "ports": [443],
            "methods": ["GET", "HEAD", "OPTIONS"],
            "max_rps": 1,
        }
    ]
    if include_wildcard:
        targets.append(
            {
                "pattern": "*.example.com",
                "schemes": ["https"],
                "ports": [443],
                "methods": ["GET", "HEAD", "OPTIONS"],
                "max_rps": 1,
            }
        )
    _write_json(
        path,
        {
            "name": "authorized-test",
            "active_testing": True,
            "human_approval_required": True,
            "targets": targets,
        },
    )


def test_prioritizer_prefers_object_access_and_deduplicates_routes() -> None:
    engine = EndpointPrioritizer()
    leads = engine.prioritize(
        [
            "https://api.example.com/users/12345?view=full",
            "https://api.example.com/users/67890?view=compact",
            "https://api.example.com/fetch?url=https%3A%2F%2Fexample.org",
            "https://api.example.com/search?q=test&page=2",
        ]
    )
    object_leads = [lead for lead in leads if lead.kind == "object-access"]
    assert len(object_leads) == 1
    assert object_leads[0].score >= 88
    assert "users/{id}" in object_leads[0].route
    assert any(lead.kind == "server-side-fetch-surface" for lead in leads)


@pytest.mark.parametrize(
    ("url", "kind"),
    [
        ("https://a.example.com/go?next=%2Fhome", "redirect-callback-surface"),
        ("https://a.example.com/download?path=%2Ftmp%2Fx", "file-path-surface"),
        ("https://a.example.com/admin/debug", "privileged-surface"),
        ("https://a.example.com/graphql", "api-introspection-surface"),
        ("https://a.example.com/upload", "file-workflow-surface"),
        ("https://a.example.com/oauth/login", "identity-flow-surface"),
        ("https://a.example.com/search?q=x", "parameterized-surface"),
    ],
)
def test_prioritizer_classifies_high_value_surfaces(url: str, kind: str) -> None:
    lead = EndpointPrioritizer().classify(url)
    assert lead is not None
    assert lead.kind == kind


def test_prioritizer_ignores_non_http_and_empty_inputs() -> None:
    engine = EndpointPrioritizer()
    assert engine.classify("") is None
    assert engine.classify("ftp://example.com/file?id=1") is None


def test_bounty_runner_refuses_without_explicit_authorization(tmp_path: Path) -> None:
    _policy(tmp_path / "policy.json")
    _write_json(
        tmp_path / "campaign.json",
        {"name": "x", "domain": "example.com", "policy": "policy.json"},
    )
    with pytest.raises(BountyError, match="authorized_testing"):
        BountyRunner(command_runner=lambda *_: None).run(
            tmp_path / "campaign.json", tmp_path / "out"
        )


def test_bounty_runner_requires_root_and_wildcard_scope(tmp_path: Path) -> None:
    _policy(tmp_path / "policy.json", include_wildcard=False)
    script = tmp_path / "bb-pipeline.sh"
    script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    _write_json(
        tmp_path / "campaign.json",
        {
            "domain": "example.com",
            "policy": "policy.json",
            "recon_script": "bb-pipeline.sh",
            "authorized_testing": True,
        },
    )
    with pytest.raises(BountyError, match="root domain and its wildcard"):
        BountyRunner(command_runner=lambda *_: None).run(
            tmp_path / "campaign.json", tmp_path / "out"
        )


def test_bounty_runner_builds_ranked_board_merges_verification_and_tracks_delta(
    tmp_path: Path,
) -> None:
    _policy(tmp_path / "policy.json")
    script = tmp_path / "bb-pipeline.sh"
    script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    _write_json(tmp_path / "verification.json", {})
    _write_json(
        tmp_path / "campaign.json",
        {
            "name": "authorized-bounty",
            "domain": "example.com",
            "policy": "policy.json",
            "recon_script": "bb-pipeline.sh",
            "verification_manifest": "verification.json",
            "authorized_testing": True,
            "max_leads": 20,
            "recon": {"env": {"NUCLEI_RPS": "1", "KATANA_RPS": "1"}},
        },
    )

    def fake_runner(command: list[str], cwd: Path, env: object) -> None:
        assert cwd == tmp_path
        assert isinstance(env, dict)
        assert env["NUCLEI_RPS"] == "1"
        assert env["HTTPX_RPS"] == "1"
        out = Path(command[command.index("-o") + 1])
        run = out / "example.com" / "20260912_230000"
        (run / "crawl").mkdir(parents=True, exist_ok=True)
        (run / "scan").mkdir(parents=True, exist_ok=True)
        (run / "report").mkdir(parents=True, exist_ok=True)
        (run / "crawl" / "logic_idor_candidates.txt").write_text(
            "https://api.example.com/accounts/123456?detail=1\n",
            encoding="utf-8",
        )
        (run / "crawl" / "parameter_urls.txt").write_text(
            "https://api.example.com/fetch?url=https%3A%2F%2Fexample.org\n",
            encoding="utf-8",
        )
        (run / "scan" / "nuclei_findings.jsonl").write_text(
            "not-json\n"
            + json.dumps(
                {
                    "template-id": "example-high",
                    "info": {"severity": "high"},
                    "matched-at": "https://api.example.com/debug",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (run / "report" / "summary.md").write_text("ok\n", encoding="utf-8")

    class FakeVerificationResult:
        def to_dict(self) -> dict[str, object]:
            return {
                "observation_count": 6,
                "candidate_count": 1,
                "verified_count": 1,
                "top_candidates": [
                    {
                        "id": "cand-1",
                        "title": "Non-owner received another controlled principal's object",
                        "target": "GET /accounts/{id}",
                        "verification_strength": "verified",
                    }
                ],
            }

    class FakeVerificationRunner:
        def run(self, manifest: Path, output: Path) -> FakeVerificationResult:
            assert manifest == (tmp_path / "verification.json").resolve()
            assert output == (tmp_path / "out" / "verification").resolve()
            return FakeVerificationResult()

    output = tmp_path / "out"
    runner = BountyRunner(
        command_runner=fake_runner,
        verification_runner=FakeVerificationRunner(),  # type: ignore[arg-type]
    )
    first = runner.run(tmp_path / "campaign.json", output)
    assert first.lead_count == 4
    assert first.verified_count == 1
    assert first.scanner_signal_count == 1
    assert first.new_lead_count == 4
    board = json.loads((output / "bounty-board.json").read_text(encoding="utf-8"))
    assert board[0]["confidence"] == "verified"
    assert {item["kind"] for item in board} >= {
        "nuclei:example-high",
        "object-access",
        "server-side-fetch-surface",
    }
    report = (output / "bounty-report.md").read_text(encoding="utf-8")
    assert "Controlled verification" in report
    assert "Verified: **1**" in report

    second = runner.run(tmp_path / "campaign.json", output)
    assert second.new_lead_count == 0


def test_bounty_runner_rejects_domain_outside_policy(tmp_path: Path) -> None:
    _policy(tmp_path / "policy.json")
    script = tmp_path / "bb-pipeline.sh"
    script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    _write_json(
        tmp_path / "campaign.json",
        {
            "domain": "other.example",
            "policy": "policy.json",
            "recon_script": "bb-pipeline.sh",
            "authorized_testing": True,
        },
    )
    with pytest.raises(BountyError, match="root domain and its wildcard"):
        BountyRunner(command_runner=lambda *_: None).run(
            tmp_path / "campaign.json", tmp_path / "out"
        )


def test_bounty_mode_binds_rate_overrides_to_policy_ceiling() -> None:
    defaults = BountyRunner._bounded_env({}, ceiling=1)
    assert defaults["HTTPX_RPS"] == "1"
    assert defaults["KATANA_RPS"] == "1"
    assert defaults["NUCLEI_RPS"] == "1"
    with pytest.raises(BountyError, match="policy ceiling of 1 rps"):
        BountyRunner._bounded_env({"env": {"NUCLEI_RPS": "2"}}, ceiling=1)
