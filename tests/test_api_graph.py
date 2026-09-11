import pytest

from barq_crs.api_graph import OpenApiDependencyGraph


def document():
    return {
        "openapi": "3.1.0",
        "security": [{"bearer": []}],
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "email": {"type": "string"},
                    },
                }
            }
        },
        "paths": {
            "/v1/users": {
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"email": {"type": "string"}},
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        }
                    },
                }
            },
            "/v1/users/{userId}": {
                "get": {
                    "operationId": "getUser",
                    "parameters": [
                        {"name": "userId", "in": "path", "required": True}
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }


def test_operation_model_resolves_schema_references():
    operations = OpenApiDependencyGraph().operations(document())
    create = next(item for item in operations if item.operation_id == "createUser")
    assert {"id", "user_id", "email"} <= set(create.produces)
    assert create.authenticated is True


def test_infers_producer_consumer_edge():
    engine = OpenApiDependencyGraph()
    edges = engine.edges(engine.operations(document()))
    edge = next(
        item
        for item in edges
        if item.producer == "createUser" and item.consumer == "getUser"
    )
    assert "user_id" in edge.fields


def test_builds_stateful_sequence():
    sequences = OpenApiDependencyGraph().sequences(document(), max_depth=3)
    assert any(item.operations == ("createUser", "getUser") for item in sequences)


def test_operation_level_anonymous_override():
    value = document()
    value["paths"]["/v1/users/{userId}"]["get"]["security"] = []
    get_user = next(
        item
        for item in OpenApiDependencyGraph().operations(value)
        if item.operation_id == "getUser"
    )
    assert get_user.authenticated is False


def test_sequence_depth_is_bounded():
    with pytest.raises(ValueError, match="between 2 and 6"):
        OpenApiDependencyGraph().sequences(document(), max_depth=20)


def test_missing_local_reference_does_not_crash_modeling():
    value = document()
    value["paths"]["/v1/users"]["post"]["responses"]["201"]["content"][
        "application/json"
    ]["schema"] = {"$ref": "#/components/schemas/Missing"}
    operations = OpenApiDependencyGraph().operations(value)
    create = next(item for item in operations if item.operation_id == "createUser")
    assert create.produces == ()
