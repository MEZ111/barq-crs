from __future__ import annotations

import pytest

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
