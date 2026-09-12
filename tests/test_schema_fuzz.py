import pytest

from barq_crs.schema_fuzz import OpenApiTestPlanner


def document():
    return {
        "openapi": "3.1.0",
        "security": [{"bearer": []}],
        "components": {
            "schemas": {
                "UpdateUser": {
                    "type": "object",
                    "properties": {
                        "display_name": {"type": "string", "maxLength": 40},
                        "is_admin": {"type": "boolean", "readOnly": True},
                        "team_id": {"type": "integer"},
                        "quota": {"type": "integer", "minimum": 0, "maximum": 10},
                        "callback": {"type": "string", "format": "uri"},
                    },
                }
            }
        },
        "paths": {
            "/v1/users/{userId}": {
                "parameters": [{"name": "userId", "in": "path", "schema": {"type": "integer"}}],
                "get": {
                    "operationId": "getUser",
                    "parameters": [{"name": "expand", "in": "query", "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "ok"}},
                },
                "patch": {
                    "operationId": "updateUser",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UpdateUser"}
                            }
                        }
                    },
                    "responses": {"200": {"description": "ok"}},
                },
            }
        },
    }


def categories(cases, operation_id=None):
    return {
        case.category
        for case in cases
        if operation_id is None or case.operation_id == operation_id
    }


def test_builds_controlled_identity_differential():
    cases = OpenApiTestPlanner().plan(document())
    case = next(item for item in cases if item.operation_id == "getUser" and item.category == "authorization-differential")
    assert "Two researcher-controlled identities" in case.preconditions
    assert case.isolated_only is False


def test_builds_bola_object_swap_for_camel_case_path_identifier():
    cases = OpenApiTestPlanner().plan(document())
    case = next(
        item
        for item in cases
        if item.operation_id == "getUser" and item.category == "object-boundary-swap"
    )
    assert case.risk == "critical"
    assert case.mutations[0].field == "userId"


def test_builds_mass_assignment_case_for_privileged_field():
    cases = OpenApiTestPlanner().plan(document())
    case = next(
        item
        for item in cases
        if item.operation_id == "updateUser" and item.category == "mass-assignment-boundary" and item.mutations[0].field == "is_admin"
    )
    assert case.risk == "critical"
    assert case.isolated_only is True


def test_builds_foreign_object_binding_for_body_id():
    cases = OpenApiTestPlanner().plan(document())
    case = next(
        item
        for item in cases
        if item.operation_id == "updateUser"
        and item.category == "foreign-object-binding"
        and item.mutations[0].field == "team_id"
    )
    assert "controlled identities" in " ".join(case.preconditions)


def test_builds_query_parameter_pollution_case():
    cases = OpenApiTestPlanner().plan(document())
    case = next(item for item in cases if item.category == "http-parameter-pollution")
    assert case.mutations[0].location == "query"
    assert case.mutations[0].strategy == "duplicate-key"


def test_builds_numeric_and_type_boundaries():
    cases = OpenApiTestPlanner().plan(document())
    quota = [
        item
        for item in cases
        if item.operation_id == "updateUser" and item.mutations[0].field == "quota"
    ]
    assert {item.category for item in quota} >= {"numeric-boundary", "type-confusion"}
    numeric = next(item for item in quota if item.category == "numeric-boundary")
    assert "maximum plus one" in numeric.mutations[0].value_shape


def test_builds_uri_canonicalization_case():
    cases = OpenApiTestPlanner().plan(document())
    case = next(item for item in cases if item.category == "canonicalization-differential")
    assert case.mutations[0].field == "callback"
    assert any("Researcher-controlled destination" in item for item in case.preconditions)


def test_write_operations_are_always_isolated_and_approval_gated():
    cases = [item for item in OpenApiTestPlanner().plan(document()) if item.operation_id == "updateUser"]
    assert cases
    assert all(item.isolated_only and item.requires_human_approval for item in cases)


def test_anonymous_operation_does_not_get_identity_case():
    value = document()
    value["paths"]["/v1/users/{userId}"]["get"]["security"] = []
    cases = OpenApiTestPlanner().plan(value)
    assert "authorization-differential" not in categories(cases, "getUser")


def test_openapi_two_body_parameter_is_supported():
    value = {
        "swagger": "2.0",
        "security": [{"key": []}],
        "paths": {
            "/v1/records": {
                "post": {
                    "operationId": "createRecord",
                    "parameters": [
                        {
                            "name": "record",
                            "in": "body",
                            "schema": {
                                "type": "object",
                                "properties": {"owner_id": {"type": "string"}},
                            },
                        }
                    ],
                }
            }
        },
    }
    cases = OpenApiTestPlanner().plan(value)
    assert "mass-assignment-boundary" in categories(cases, "createRecord")


def test_case_budget_is_enforced_and_deterministic():
    planner = OpenApiTestPlanner()
    first = planner.plan(document(), max_cases=4)
    second = planner.plan(document(), max_cases=4)
    assert len(first) == 4
    assert [item.id for item in first] == [item.id for item in second]


@pytest.mark.parametrize("limit", [0, 2001])
def test_rejects_unbounded_case_limit(limit):
    with pytest.raises(ValueError, match="between 1 and 2000"):
        OpenApiTestPlanner().plan(document(), max_cases=limit)


def test_unresolved_reference_does_not_crash():
    value = document()
    value["paths"]["/v1/users/{userId}"]["patch"]["requestBody"]["content"]["application/json"]["schema"] = {
        "$ref": "#/components/schemas/Missing"
    }
    cases = OpenApiTestPlanner().plan(value)
    assert any(item.operation_id == "updateUser" for item in cases)
