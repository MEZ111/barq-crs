from barq_crs.drift import ContractDriftEngine


def test_security_removal_is_detected():
    before = {"security": [{"bearer": []}], "paths": {"/v1/account": {"get": {}}}}
    after = {"security": [{"bearer": []}], "paths": {"/v1/account": {"get": {"security": []}}}}
    findings = ContractDriftEngine().analyze(before, after)
    assert len(findings) == 1
    assert findings[0].kind == "authentication-removed"


def test_new_public_health_route_is_not_sensitive():
    before = {"paths": {}}
    after = {"paths": {"/health": {"get": {"security": []}}}}
    assert ContractDriftEngine().analyze(before, after) == []


def test_new_anonymous_admin_route_is_detected():
    findings = ContractDriftEngine().analyze(
        {"paths": {}}, {"paths": {"/internal/admin/export": {"get": {"security": []}}}}
    )
    assert findings[0].kind == "new-sensitive-anonymous-operation"
