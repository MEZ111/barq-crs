from __future__ import annotations

import json
from pathlib import Path

import pytest

from barq_crs.bounty import BountyResult
from barq_crs.scope import ScopePolicy
from barq_crs.smart_verify import (
    DiscoveryTemplateSynthesizer,
    SmartBountyRunner,
    SmartVerificationError,
    SynthesizedTemplate,
)
from barq_crs.verifier import ControlledResource, RequestTemplate


def _policy() -> ScopePolicy:
    return ScopePolicy.from_dict(
        {
            "name": "authorized",
            "active_testing": True,
            "targets": [
                {
                    "pattern": "api.example.com",
                    "schemes": ["https"],
                    "ports": [443],
                    "methods": ["GET", "HEAD", "OPTIONS"],
                    "max_rps": 1,
                }
            ],
        }
    )


def _resources() -> list[ControlledResource]:
    return [
        ControlledResource(
            key="alice-user",
            kind="user",
            value="alice-controlled-123456",
            owner="alice",
            tenant="red",
        ),
        ControlledResource(
            key="bob-user",
            kind="user",
            value="bob-controlled-654321",
            owner="bob",
            tenant="blue",
        ),
    ]


def test_exact_controlled_path_becomes_safe_template() -> None:
    generated = DiscoveryTemplateSynthesizer().synthesize(
        ["https://api.example.com/users/alice-controlled-123456?view=full"],
        _resources(),
        _policy(),
    )
    assert generated
    template = generated[0].template
    assert template.resource_kind == "user"
    assert "{resource}" in template.url
    assert "alice-controlled-123456" not in template.url


def test_explicit_query_binding_replaces_discovered_value() -> None:
    generated = DiscoveryTemplateSynthesizer().synthesize(
        ["https://api.example.com/profile?user_id=historical-third-party-value"],
        _resources(),
        _policy(),
        parameter_bindings={"user_id": "user"},
    )
    assert len(generated) == 1
    assert "user_id={resource}" in generated[0].template.url
    assert "historical-third-party-value" not in generated[0].template.url


def test_kind_path_inference_uses_controlled_resource_only() -> None:
    generated = DiscoveryTemplateSynthesizer().synthesize(
        ["https://api.example.com/users/987654321"],
        _resources(),
        _policy(),
    )
    assert len(generated) == 1
    assert generated[0].template.url == "https://api.example.com/users/{resource}"
    assert generated[0].template.resource_kind == "user"


def test_out_of_scope_discovery_is_dropped() -> None:
    generated = DiscoveryTemplateSynthesizer().synthesize(
        ["https://evil.example/users/987654321"],
        _resources(),
        _policy(),
    )
    assert generated == []


def test_unknown_parameter_binding_is_rejected() -> None:
    with pytest.raises(SmartVerificationError, match="unknown resource kinds"):
        DiscoveryTemplateSynthesizer().synthesize(
            ["https://api.example.com/orders?id=1"],
            _resources(),
            _policy(),
            parameter_bindings={"id": "order"},
        )


def test_budget_fitter_prefers_high_score_templates() -> None:
    resources = _resources()
    high = SynthesizedTemplate(
        RequestTemplate(
            name="high",
            url="https://api.example.com/users/{resource}",
            resource_kind="user",
        ),
        99,
        "https://api.example.com/users/123",
        "high",
    )
    low = SynthesizedTemplate(
        RequestTemplate(
            name="low",
            url="https://api.example.com/profiles/{resource}",
            resource_kind="user",
        ),
        60,
        "https://api.example.com/profiles/123",
        "low",
    )
    selected, used = SmartBountyRunner._fit_budget(
        [], [], [high, low], resources, profile_count=3, max_requests=6
    )
    assert selected == [high]
    assert used == 6


def test_existing_plan_cannot_silently_overrun_budget() -> None:
    existing = [
        RequestTemplate(
            name="existing",
            url="https://api.example.com/users/{resource}",
            resource_kind="user",
        )
    ]
    with pytest.raises(SmartVerificationError, match="already exceeds request budget"):
        SmartBountyRunner._fit_budget(
            existing,
            [],
            [],
            _resources(),
            profile_count=3,
            max_requests=5,
        )


def test_smart_bounty_runner_turns_recon_edge_into_verified_board_item(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign.json"
    verification = tmp_path / "verification.json"
    policy = tmp_path / "policy.json"
    profiles = tmp_path / "profiles.json"
    resources = tmp_path / "resources.json"
    output = tmp_path / "out"
    recon_run = output / "fake-recon"
    (recon_run / "crawl").mkdir(parents=True)
    (recon_run / "crawl" / "all_scoped_urls.txt").write_text(
        "https://api.example.com/users/987654321\n", encoding="utf-8"
    )
    policy.write_text(
        json.dumps(
            {
                "name": "authorized",
                "active_testing": True,
                "targets": [
                    {
                        "pattern": "api.example.com",
                        "schemes": ["https"],
                        "ports": [443],
                        "methods": ["GET", "HEAD", "OPTIONS"],
                        "max_rps": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    profiles.write_text(
        json.dumps(
            [
                {"principal": "alice", "role": "user", "headers": {}},
                {"principal": "bob", "role": "user", "headers": {}},
            ]
        ),
        encoding="utf-8",
    )
    resources.write_text(
        json.dumps(
            [
                {
                    "key": "alice-user",
                    "kind": "user",
                    "value": "alice-controlled-123456",
                    "owner": "alice",
                },
                {
                    "key": "bob-user",
                    "kind": "user",
                    "value": "bob-controlled-654321",
                    "owner": "bob",
                },
            ]
        ),
        encoding="utf-8",
    )
    verification.write_text(
        json.dumps(
            {
                "name": "smart-test",
                "policy": "policy.json",
                "profiles": "profiles.json",
                "resources": "resources.json",
                "templates": [],
                "include_anonymous": True,
                "limits": {"max_requests": 6},
            }
        ),
        encoding="utf-8",
    )
    campaign.write_text(
        json.dumps(
            {
                "name": "smart-bounty",
                "max_leads": 20,
                "smart_verification": {
                    "manifest": "verification.json",
                    "max_templates": 10,
                },
            }
        ),
        encoding="utf-8",
    )

    class FakeBaseRunner:
        def run(self, _manifest: Path, out: Path) -> BountyResult:
            out.mkdir(parents=True, exist_ok=True)
            (out / "bounty-board.json").write_text("[]\n", encoding="utf-8")
            (out / "state.json").write_text("{}\n", encoding="utf-8")
            return BountyResult(
                campaign="smart-bounty",
                domain="example.com",
                output_directory=str(out),
                recon_run=str(recon_run),
                lead_count=0,
                verified_count=0,
                scanner_signal_count=0,
                new_lead_count=0,
                artifacts={
                    "board": str(out / "bounty-board.json"),
                    "report": str(out / "bounty-report.md"),
                    "state": str(out / "state.json"),
                },
                top_leads=(),
            )

    class FakeVerificationResult:
        def to_dict(self) -> dict[str, object]:
            summary_path = output / "smart-verification" / "summary.json"
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            summary_path.write_text("{}\n", encoding="utf-8")
            return {
                "observation_count": 6,
                "candidate_count": 1,
                "verified_count": 1,
                "artifacts": {"summary": str(summary_path)},
                "top_candidates": [
                    {
                        "id": "bola-1",
                        "kind": "bola",
                        "target": "GET /users/{id}",
                        "verification_strength": "verified",
                    }
                ],
            }

    class FakeVerificationRunner:
        derived_path: Path | None = None
        derived: dict[str, object] | None = None

        def run(self, manifest_path: Path, _out: Path) -> FakeVerificationResult:
            self.derived_path = Path(manifest_path)
            self.derived = json.loads(self.derived_path.read_text(encoding="utf-8"))
            return FakeVerificationResult()

    fake_verifier = FakeVerificationRunner()
    result = SmartBountyRunner(
        base_runner=FakeBaseRunner(),  # type: ignore[arg-type]
        verification_runner=fake_verifier,  # type: ignore[arg-type]
    ).run(campaign, output)

    assert result.verified_count == 1
    assert result.lead_count == 1
    assert fake_verifier.derived is not None
    derived_text = json.dumps(fake_verifier.derived)
    assert "https://api.example.com/users/{resource}" in derived_text
    assert "987654321" not in derived_text
    assert fake_verifier.derived_path is not None
    assert not fake_verifier.derived_path.exists()
    plan = json.loads((output / "smart-verification-plan.json").read_text(encoding="utf-8"))
    assert plan["estimated_request_count"] == 6
    assert plan["selected_template_count"] == 1
