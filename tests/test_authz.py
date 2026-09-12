from barq_crs.authz import AuthorizationDifferentialEngine, response_summary
from barq_crs.models import Observation


def obs(**changes):
    value = dict(
        timestamp="2026-09-11T00:00:00Z",
        method="GET",
        url="https://lab.test/api/users/7",
        route="/api/users/{id}",
        principal="alice",
        role="user",
        status=200,
        body={"user_id": 7, "email": "controlled@example.test"},
        resource_id="7",
        owns_resource=True,
        principal_tenant="red",
        resource_tenant="red",
    )
    value.update(changes)
    return Observation(**value)


def test_cross_principal_object_access():
    findings = AuthorizationDifferentialEngine().analyze(
        [obs(), obs(principal="bob", owns_resource=False)]
    )
    finding = next(item for item in findings if item.kind == "cross-principal-object-access")
    assert finding.evidence[0].metadata["verification_strength"] == "verified"


def test_cross_tenant_access():
    findings = AuthorizationDifferentialEngine().analyze(
        [
            obs(),
            obs(principal="bob", owns_resource=False, principal_tenant="blue"),
        ]
    )
    finding = next(item for item in findings if item.kind == "cross-tenant-access")
    assert finding.evidence[0].metadata["verification_strength"] == "verified"


def test_anonymous_sensitive_response():
    findings = AuthorizationDifferentialEngine().analyze(
        [
            obs(),
            obs(principal="anonymous", role="anonymous", owns_resource=None),
        ]
    )
    finding = next(item for item in findings if item.kind == "anonymous-sensitive-response")
    assert finding.evidence[0].metadata["matches_authenticated_baseline"] is True


def test_failed_response_is_not_flagged():
    findings = AuthorizationDifferentialEngine().analyze(
        [obs(principal="anonymous", role="anonymous", status=401, body={"email": "x"})]
    )
    assert findings == []


def test_2xx_denial_body_is_not_flagged():
    findings = AuthorizationDifferentialEngine().analyze(
        [
            obs(),
            obs(
                principal="bob",
                owns_resource=False,
                principal_tenant="blue",
                body={"message": "Not found", "code": "NOT_FOUND"},
            ),
        ]
    )
    assert findings == []


def test_volatile_response_fields_do_not_break_verified_match():
    owner = obs(
        body={
            "user_id": 7,
            "email": "controlled@example.test",
            "request_id": "one",
            "updated_at": "2026-09-12T01:00:00Z",
        }
    )
    viewer = obs(
        principal="bob",
        owns_resource=False,
        principal_tenant="blue",
        body={
            "user_id": 7,
            "email": "controlled@example.test",
            "request_id": "two",
            "updated_at": "2026-09-12T01:00:05Z",
        },
    )
    finding = next(
        item
        for item in AuthorizationDifferentialEngine().analyze([owner, viewer])
        if item.kind == "cross-principal-object-access"
    )
    assert finding.evidence[0].metadata["verification_strength"] == "verified"
    assert finding.evidence[0].metadata["same_response"] is True


def test_same_sensitive_field_names_with_different_values_are_not_marked_verified():
    owner = obs(body={"user_id": "alice", "email": "alice@example.test"})
    viewer = obs(
        principal="bob",
        owns_resource=False,
        body={"user_id": "bob", "email": "bob@example.test"},
    )
    findings = AuthorizationDifferentialEngine().analyze([owner, viewer])
    finding = next(item for item in findings if item.kind == "cross-principal-object-access")
    assert finding.evidence[0].metadata["verification_strength"] == "likely"
    assert finding.evidence[0].metadata["matching_sensitive_keys"] == []


def test_sensitive_key_matching_is_case_insensitive():
    summary = response_summary({"Email": "controlled@example.test", "User-ID": 7})
    assert "Email" in summary["sensitive_keys"]
    assert "User-ID" in summary["sensitive_keys"]


def test_report_evidence_does_not_store_raw_body():
    findings = AuthorizationDifferentialEngine().analyze(
        [obs(), obs(principal="bob", owns_resource=False)]
    )
    serialized = str(findings[0].to_dict())
    assert "controlled@example.test" not in serialized
