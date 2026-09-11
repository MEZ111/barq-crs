from barq_crs.authz import AuthorizationDifferentialEngine
from barq_crs.models import Observation


def obs(**changes):
    value = dict(
        timestamp="2026-09-11T00:00:00Z", method="GET", url="https://lab.test/api/users/7",
        route="/api/users/{id}", principal="alice", role="user", status=200,
        body={"user_id": 7, "email": "controlled@example.test"}, resource_id="7",
        owns_resource=True, principal_tenant="red", resource_tenant="red",
    )
    value.update(changes)
    return Observation(**value)


def test_cross_principal_object_access():
    findings = AuthorizationDifferentialEngine().analyze([
        obs(), obs(principal="bob", owns_resource=False),
    ])
    assert any(item.kind == "cross-principal-object-access" for item in findings)


def test_cross_tenant_access():
    findings = AuthorizationDifferentialEngine().analyze([
        obs(principal="bob", owns_resource=False, principal_tenant="blue"),
    ])
    assert any(item.kind == "cross-tenant-access" for item in findings)


def test_anonymous_sensitive_response():
    findings = AuthorizationDifferentialEngine().analyze([
        obs(principal="anonymous", role="anonymous", owns_resource=None),
    ])
    assert findings[0].kind == "anonymous-sensitive-response"


def test_failed_response_is_not_flagged():
    findings = AuthorizationDifferentialEngine().analyze([
        obs(principal="anonymous", role="anonymous", status=401, body={"email": "x"}),
    ])
    assert findings == []


def test_report_evidence_does_not_store_raw_body():
    findings = AuthorizationDifferentialEngine().analyze([obs(), obs(principal="bob", owns_resource=False)])
    assert "controlled@example.test" not in str(findings[0].to_dict())
