from barq_crs.drift import ContractDriftEngine


def kinds(before, after):
    return {finding.kind for finding in ContractDriftEngine().analyze(before, after)}


def test_security_removal_is_detected():
    before = {"security": [{"bearer": []}], "paths": {"/v1/account": {"get": {}}}}
    after = {
        "security": [{"bearer": []}],
        "paths": {"/v1/account": {"get": {"security": []}}},
    }
    findings = ContractDriftEngine().analyze(before, after)
    assert len(findings) == 1
    assert findings[0].kind == "authentication-removed"


def test_new_public_health_route_is_not_sensitive():
    before = {"paths": {}}
    after = {"paths": {"/health": {"get": {"security": []}}}}
    assert ContractDriftEngine().analyze(before, after) == []


def test_new_anonymous_admin_route_is_detected():
    findings = ContractDriftEngine().analyze(
        {"paths": {}},
        {"paths": {"/internal/admin/export": {"get": {"security": []}}}},
    )
    assert findings[0].kind == "new-sensitive-anonymous-operation"


def test_weaker_or_alternative_is_detected():
    before = {
        "paths": {
            "/v1/account": {
                "get": {"security": [{"oauth": ["read", "admin"]}]}
            }
        }
    }
    after = {
        "paths": {
            "/v1/account": {
                "get": {
                    "security": [
                        {"oauth": ["read", "admin"]},
                        {"oauth": ["read"]},
                    ]
                }
            }
        }
    }
    assert "weaker-security-alternative-added" in kinds(before, after)


def test_removing_and_scheme_is_detected():
    before = {
        "paths": {
            "/v1/account": {
                "get": {"security": [{"oauth": ["read"], "apiKey": []}]}
            }
        }
    }
    after = {
        "paths": {
            "/v1/account": {"get": {"security": [{"oauth": ["read"]}]}}
        }
    }
    assert "required-security-scheme-removed" in kinds(before, after)


def test_removing_scope_is_detected():
    before = {
        "paths": {
            "/v1/account": {
                "get": {"security": [{"oauth": ["read", "admin"]}]}
            }
        }
    }
    after = {
        "paths": {
            "/v1/account": {"get": {"security": [{"oauth": ["read"]}]}}
        }
    }
    assert "required-scope-removed" in kinds(before, after)


def test_removing_weaker_or_alternative_is_not_regression():
    before = {
        "paths": {
            "/v1/account": {
                "get": {
                    "security": [
                        {"oauth": ["read"]},
                        {"oauth": ["read", "admin"]},
                    ]
                }
            }
        }
    }
    after = {
        "paths": {
            "/v1/account": {
                "get": {"security": [{"oauth": ["read", "admin"]}]}
            }
        }
    }
    assert ContractDriftEngine().analyze(before, after) == []


def test_replacing_scope_name_does_not_invent_scope_hierarchy():
    before = {
        "paths": {
            "/v1/account": {"get": {"security": [{"oauth": ["admin"]}]}}
        }
    }
    after = {
        "paths": {
            "/v1/account": {"get": {"security": [{"oauth": ["read"]}]}}
        }
    }
    assert ContractDriftEngine().analyze(before, after) == []


def test_security_scheme_definition_and_type_changes_are_reported():
    before = {
        "components": {
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer"},
                "legacy": {"type": "apiKey", "in": "header", "name": "X-Key"},
            }
        },
        "paths": {},
    }
    after = {
        "components": {
            "securitySchemes": {
                "bearer": {"type": "apiKey", "in": "header", "name": "X-Auth"}
            }
        },
        "paths": {},
    }
    result = kinds(before, after)
    assert "security-scheme-definition-removed" in result
    assert "security-scheme-type-changed" in result
