import pytest

from barq_crs.collector import (
    CollectionError,
    CollectorLimits,
    EvidenceCollector,
    RequestSpec,
    SessionProfile,
)
from barq_crs.authz import AuthorizationDifferentialEngine
from barq_crs.scope import ScopePolicy, ScopeViolation


class Response:
    status = 200
    headers = {"Content-Type": "application/json"}

    def __init__(self, body=b'{"user_id":7,"email":"owned@test"}'):
        self.body = body

    def read(self, _limit):
        return self.body


class Opener:
    def __init__(self, response=None):
        self.response = response or Response()
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return self.response


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


def profile():
    return SessionProfile("owner", "user", {"Authorization": "Bearer fixture"}, "red")


def test_collects_json_without_persisting_headers():
    opener = Opener()
    observation = EvidenceCollector(policy(), opener=opener, clock=lambda: 0).collect_one(
        RequestSpec("https://lab.example.test/api/users/7", route="/api/users/{id}"),
        profile(),
    )
    assert observation.status == 200
    assert observation.body["user_id"] == 7
    assert observation.principal_tenant == "red"
    assert "Bearer fixture" not in str(observation)
    assert opener.requests[0][0].get_header("Authorization") == "Bearer fixture"


def test_collector_rejects_state_changing_method():
    with pytest.raises(ScopeViolation, match="read-only"):
        EvidenceCollector(policy(), opener=Opener()).collect_one(
            RequestSpec("https://lab.example.test/api", method="POST"), profile()
        )


def test_collector_rejects_out_of_scope_target():
    with pytest.raises(ScopeViolation, match="not explicitly authorized"):
        EvidenceCollector(policy(), opener=Opener()).collect_one(
            RequestSpec("https://outside.example/api"), profile()
        )


def test_matrix_budget_is_enforced_before_network():
    collector = EvidenceCollector(
        policy(), CollectorLimits(max_requests=1), opener=Opener()
    )
    with pytest.raises(CollectionError, match="exceeds budget"):
        collector.collect_matrix(
            [RequestSpec("https://lab.example.test/a")],
            [profile(), SessionProfile("other", "user", {})],
        )


def test_body_limit_marks_truncation():
    collector = EvidenceCollector(
        policy(),
        CollectorLimits(max_body_bytes=4),
        opener=Opener(Response(b"123456")),
        clock=lambda: 0,
    )
    observation = collector.collect_one(
        RequestSpec("https://lab.example.test/a"), profile()
    )
    assert observation.body == 1234
    assert "truncated" in observation.tags


def test_profile_resolves_secrets_from_environment():
    value = SessionProfile.from_env_dict(
        {
            "principal": "owner",
            "role": "admin",
            "header_env": {"Authorization": "BARQ_AUTH"},
            "static_headers": {"X-Research-ID": "case-7"},
        },
        {"BARQ_AUTH": "Bearer fixture"},
    )
    assert value.headers["Authorization"] == "Bearer fixture"
    assert value.headers["X-Research-ID"] == "case-7"


def test_profile_rejects_secret_in_static_config():
    with pytest.raises(CollectionError, match="environment binding"):
        SessionProfile.from_env_dict(
            {"principal": "x", "static_headers": {"Cookie": "secret"}}, {}
        )


def test_profile_requires_bound_environment_variable():
    with pytest.raises(CollectionError, match="missing"):
        SessionProfile.from_env_dict(
            {"principal": "x", "header_env": {"Cookie": "BARQ_COOKIE"}}, {}
        )


def test_live_matrix_flows_into_authorization_analysis():
    collector = EvidenceCollector(
        policy(), opener=Opener(), clock=lambda: 0, sleeper=lambda _seconds: None
    )
    observations = collector.collect_matrix(
        [
            RequestSpec(
                "https://lab.example.test/api/users/7",
                route="/api/users/{id}",
                resource_id="7",
                resource_tenant="red",
            )
        ],
        [
            SessionProfile(
                "owner", "user", {}, "red", frozenset({"7"})
            ),
            SessionProfile(
                "reviewer", "user", {}, "blue", frozenset()
            ),
        ],
    )
    assert observations[0].owns_resource is True
    assert observations[1].owns_resource is False
    kinds = {
        finding.kind
        for finding in AuthorizationDifferentialEngine().analyze(observations)
    }
    assert "cross-principal-object-access" in kinds
    assert "cross-tenant-access" in kinds


def test_profile_rejects_header_line_break():
    with pytest.raises(CollectionError, match="line break"):
        SessionProfile.from_env_dict(
            {"principal": "x", "header_env": {"Authorization": "BARQ_AUTH"}},
            {"BARQ_AUTH": "Bearer ok\r\nX-Injected: yes"},
        )


@pytest.mark.parametrize(
    "values",
    [
        {"max_requests": 0},
        {"max_requests": 501},
        {"max_body_bytes": 0},
        {"max_body_bytes": 5_000_001},
        {"timeout_seconds": 0},
        {"timeout_seconds": 31},
    ],
)
def test_collector_limits_have_hard_ceiling(values):
    with pytest.raises(ValueError, match="must be between"):
        CollectorLimits(**values)
