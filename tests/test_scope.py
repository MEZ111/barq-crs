import pytest

from barq_crs.scope import ScopePolicy, ScopeViolation, canonical_url


def policy(active=False):
    return ScopePolicy.from_dict({
        "name": "lab",
        "active_testing": active,
        "targets": [{"pattern": "*.example.test", "schemes": ["https"], "ports": [443], "methods": ["GET", "POST"]}],
    })


def test_canonical_url_normalizes_host_and_path():
    assert canonical_url("HTTPS://API.Example.Test:443//v1//users?a=1#x") == "https://api.example.test/v1/users?a=1"


def test_explicit_wildcard_does_not_match_apex():
    with pytest.raises(ScopeViolation):
        policy().authorize("https://example.test/")


def test_authorizes_subdomain():
    assert policy().authorize("https://api.example.test/v1") == "https://api.example.test/v1"


def test_blocks_destructive_path_even_for_get():
    with pytest.raises(ScopeViolation, match="blocked"):
        policy().authorize("https://api.example.test/account/delete")


def test_active_mode_is_explicit():
    with pytest.raises(ScopeViolation, match="active testing"):
        policy().authorize("https://api.example.test/v1", active=True)


def test_state_change_needs_human_approval():
    with pytest.raises(ScopeViolation, match="human approval"):
        policy(active=True).authorize("https://api.example.test/v1", "POST", active=True)


def test_policy_caps_request_rate():
    with pytest.raises(ScopeViolation, match="no more than 5"):
        ScopePolicy.from_dict(
            {"targets": [{"pattern": "lab.test", "max_rps": 100}]}
        )
