import json

import pytest

from barq_crs.collector import CollectorLimits, SessionProfile
from barq_crs.models import Observation
from barq_crs.scope import ScopePolicy
from barq_crs.verifier import (
    ActiveAuthorizationVerifier,
    ControlledResource,
    OpenApiReadTemplatePlanner,
    RequestTemplate,
    VerificationError,
    VerificationRunner,
)


def policy():
    return ScopePolicy.from_dict(
        {
            "active_testing": True,
            "targets": [
                {
                    "pattern": "lab.example.test",
                    "methods": ["GET", "HEAD", "OPTIONS"],
                    "max_rps": 1,
                }
            ],
        }
    )


def profiles():
    return [
        SessionProfile("alice", "user", {}, "red"),
        SessionProfile("bob", "user", {}, "blue"),
    ]


def resources():
    return [
        ControlledResource("alice-user", "user", "alice/id", "alice", "red"),
        ControlledResource("bob-user", "user", "bob/id", "bob", "blue"),
    ]


class MatrixCollector:
    def __init__(self, _policy, _limits):
        pass

    def collect_matrix(self, requests, session_profiles):
        observations = []
        for spec in requests:
            for profile in session_profiles:
                owns = (
                    spec.resource_id in profile.owned_resource_ids
                    if profile.owned_resource_ids is not None and spec.resource_id is not None
                    else None
                )
                observations.append(
                    Observation(
                        timestamp="2026-09-12T00:00:00Z",
                        method=spec.method,
                        url=spec.url,
                        route=spec.route or "/",
                        principal=profile.principal,
                        role=profile.role,
                        status=200,
                        body={
                            "user_id": spec.resource_id,
                            "email": f"{spec.resource_id}@controlled.test",
                            "timestamp": profile.principal,
                        },
                        resource_id=spec.resource_id,
                        owns_resource=owns,
                        principal_tenant=profile.tenant,
                        resource_tenant=spec.resource_tenant,
                        tags=spec.tags,
                    )
                )
        return observations


def test_resource_template_encodes_controlled_identifier_and_uses_alias():
    template = RequestTemplate(
        "read-user",
        "https://lab.example.test/users/{resource}",
        route="/users/{id}",
        resource_kind="user",
    )
    spec = template.render(resources()[0])
    assert spec.url.endswith("/users/alice%2Fid")
    assert spec.resource_id == "alice-user"
    assert "alice/id" not in spec.resource_id


def test_template_rejects_state_changing_method():
    with pytest.raises(VerificationError, match="read-only"):
        RequestTemplate.from_dict(
            {"name": "mutate", "url": "https://lab.example.test/users/7", "method": "POST"}
        )


def test_openapi_planner_requires_explicit_resource_binding_and_skips_public():
    document = {
        "openapi": "3.1.0",
        "security": [{"bearerAuth": []}],
        "paths": {
            "/users/{id}": {"get": {"operationId": "getUser"}},
            "/teams/{team}/users/{id}": {"get": {"operationId": "teamUser"}},
            "/me": {"get": {"operationId": "me"}},
            "/health": {"get": {"operationId": "health", "security": []}},
            "/users": {"post": {"operationId": "createUser"}},
        },
    }
    plan = OpenApiReadTemplatePlanner().plan(
        document,
        base_url="https://lab.example.test/api",
        resource_parameters={"id": "user"},
    )
    by_name = {template.name: template for template in plan.templates}
    assert set(by_name) == {"getUser", "me"}
    assert by_name["getUser"].resource_kind == "user"
    assert by_name["getUser"].url.endswith("/users/{resource}")
    assert any("GET /teams/{team}/users/{id}" in item for item in plan.skipped)
    assert any("GET /health: public by contract" in item for item in plan.skipped)


def test_active_verifier_derives_ownership_adds_anonymous_and_verifies_bola():
    verifier = ActiveAuthorizationVerifier(collector_factory=MatrixCollector)
    run = verifier.run(
        policy(),
        profiles(),
        resources(),
        [
            RequestTemplate(
                "read-user",
                "https://lab.example.test/users/{resource}",
                route="/users/{id}",
                resource_kind="user",
            )
        ],
        limits=CollectorLimits(max_requests=20),
    )
    assert len(run.profiles) == 3
    assert {profile.principal for profile in run.profiles} == {"alice", "bob", "anonymous"}
    assert len(run.observations) == 6
    cross_principal = [
        finding for finding in run.candidates if finding.kind == "cross-principal-object-access"
    ]
    assert cross_principal
    assert all(
        finding.evidence[0].metadata["verification_strength"] == "verified"
        for finding in cross_principal
    )
    assert any(finding.kind == "cross-tenant-access" for finding in run.candidates)
    assert any(finding.kind == "anonymous-sensitive-response" for finding in run.candidates)


def test_matrix_budget_fails_before_collector_is_constructed():
    called = False

    def factory(_policy, _limits):
        nonlocal called
        called = True
        return MatrixCollector(_policy, _limits)

    verifier = ActiveAuthorizationVerifier(collector_factory=factory)
    with pytest.raises(VerificationError, match="before network access"):
        verifier.run(
            policy(),
            profiles(),
            resources(),
            [
                RequestTemplate(
                    "read-user",
                    "https://lab.example.test/users/{resource}",
                    resource_kind="user",
                )
            ],
            limits=CollectorLimits(max_requests=2),
        )
    assert called is False


def test_unknown_resource_owner_is_rejected():
    verifier = ActiveAuthorizationVerifier(collector_factory=MatrixCollector)
    with pytest.raises(VerificationError, match="owner is not a configured principal"):
        verifier.run(
            policy(),
            profiles(),
            [ControlledResource("x", "user", "7", "mallory")],
            [
                RequestTemplate(
                    "read-user",
                    "https://lab.example.test/users/{resource}",
                    resource_kind="user",
                )
            ],
        )


def test_duplicate_resource_values_are_rejected():
    verifier = ActiveAuthorizationVerifier(collector_factory=MatrixCollector)
    duplicate = [
        ControlledResource("a", "user", "same", "alice"),
        ControlledResource("b", "user", "same", "bob"),
    ]
    with pytest.raises(VerificationError, match="unique within each kind"):
        verifier.run(
            policy(),
            profiles(),
            duplicate,
            [
                RequestTemplate(
                    "read-user",
                    "https://lab.example.test/users/{resource}",
                    resource_kind="user",
                )
            ],
        )


def test_sanitized_evidence_contains_hashes_not_raw_body_or_url():
    observation = Observation(
        timestamp="now",
        method="GET",
        url="https://lab.example.test/users/secret-raw-id",
        route="/users/{id}",
        principal="bob",
        role="user",
        status=200,
        body={"email": "victim@example.test", "user_id": "secret-raw-id"},
        resource_id="controlled-alias",
        owns_resource=False,
    )
    sanitized = VerificationRunner._sanitized_observation(observation)
    text = json.dumps(sanitized)
    assert "victim@example.test" not in text
    assert "secret-raw-id" not in text
    assert "controlled-alias" in text
    assert sanitized["response"]["sensitive_keys"]
