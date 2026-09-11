from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Iterable


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
VERSION_SEGMENT = re.compile(r"^v\d+$", re.I)


def _snake(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()


def _resolve(document: dict[str, Any], value: Any) -> Any:
    seen: set[str] = set()
    while isinstance(value, dict) and isinstance(value.get("$ref"), str):
        reference = value["$ref"]
        if not reference.startswith("#/") or reference in seen:
            break
        seen.add(reference)
        node: Any = document
        try:
            for part in reference[2:].split("/"):
                node = node[part.replace("~1", "/").replace("~0", "~")]
        except (KeyError, TypeError):
            break
        value = node
    return value


def _schema_fields(
    document: dict[str, Any],
    schema: Any,
    *,
    depth: int = 0,
) -> set[str]:
    if depth > 6:
        return set()
    schema = _resolve(document, schema)
    if not isinstance(schema, dict):
        return set()
    fields = {_snake(name) for name in schema.get("properties", {})}
    for child in schema.get("properties", {}).values():
        fields.update(_schema_fields(document, child, depth=depth + 1))
    if "items" in schema:
        fields.update(_schema_fields(document, schema["items"], depth=depth + 1))
    for keyword in ("allOf", "oneOf", "anyOf"):
        for child in schema.get(keyword, []):
            fields.update(_schema_fields(document, child, depth=depth + 1))
    return fields


def _resource(path: str) -> str | None:
    segments = [
        _snake(part)
        for part in path.split("/")
        if part and not part.startswith("{") and not VERSION_SEGMENT.match(part)
    ]
    return segments[-1].rstrip("s") if segments else None


@dataclass(frozen=True, slots=True)
class ApiOperation:
    operation_id: str
    method: str
    path: str
    consumes: tuple[str, ...]
    produces: tuple[str, ...]
    authenticated: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DependencyEdge:
    producer: str
    consumer: str
    fields: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ApiSequence:
    operations: tuple[str, ...]
    bindings: tuple[DependencyEdge, ...]

    def to_dict(self) -> dict:
        return {
            "operations": list(self.operations),
            "bindings": [binding.to_dict() for binding in self.bindings],
        }


class OpenApiDependencyGraph:
    """Infers RESTler-style producer/consumer sequences from OpenAPI schemas."""

    def operations(self, document: dict[str, Any]) -> list[ApiOperation]:
        result = []
        global_security = document.get("security")
        for path, path_item in document.get("paths", {}).items():
            if not isinstance(path_item, dict):
                continue
            shared_parameters = path_item.get("parameters", [])
            for method, operation in path_item.items():
                if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                    continue
                operation_id = str(
                    operation.get("operationId")
                    or f"{method.lower()}_{_snake(path)}"
                )
                consumes = {
                    _snake(match)
                    for match in re.findall(r"\{([^}]+)\}", path)
                }
                parameters = [*shared_parameters, *operation.get("parameters", [])]
                for parameter in parameters:
                    parameter = _resolve(document, parameter)
                    if isinstance(parameter, dict) and parameter.get("name"):
                        consumes.add(_snake(str(parameter["name"])))
                request_body = _resolve(document, operation.get("requestBody", {}))
                if isinstance(request_body, dict):
                    for media in request_body.get("content", {}).values():
                        consumes.update(
                            _schema_fields(document, media.get("schema", {}))
                        )
                produces: set[str] = set()
                for status, response in operation.get("responses", {}).items():
                    if not str(status).startswith("2"):
                        continue
                    response = _resolve(document, response)
                    if not isinstance(response, dict):
                        continue
                    for media in response.get("content", {}).values():
                        produces.update(
                            _schema_fields(document, media.get("schema", {}))
                        )
                resource = _resource(path)
                if resource and "id" in produces:
                    produces.add(f"{resource}_id")
                security = (
                    operation["security"]
                    if "security" in operation
                    else global_security
                )
                result.append(
                    ApiOperation(
                        operation_id=operation_id,
                        method=method.upper(),
                        path=path,
                        consumes=tuple(sorted(consumes)),
                        produces=tuple(sorted(produces)),
                        authenticated=security not in (None, []),
                    )
                )
        return sorted(result, key=lambda item: item.operation_id)

    def edges(self, operations: Iterable[ApiOperation]) -> list[DependencyEdge]:
        operation_list = list(operations)
        edges = []
        for producer in operation_list:
            for consumer in operation_list:
                if producer.operation_id == consumer.operation_id:
                    continue
                fields = set(producer.produces) & set(consumer.consumes)
                if fields:
                    edges.append(
                        DependencyEdge(
                            producer.operation_id,
                            consumer.operation_id,
                            tuple(sorted(fields)),
                        )
                    )
        return sorted(edges, key=lambda edge: (edge.producer, edge.consumer))

    def sequences(
        self,
        document: dict[str, Any],
        *,
        max_depth: int = 3,
    ) -> list[ApiSequence]:
        if max_depth < 2 or max_depth > 6:
            raise ValueError("max_depth must be between 2 and 6")
        operations = self.operations(document)
        edges = self.edges(operations)
        adjacency: dict[str, list[DependencyEdge]] = {}
        for edge in edges:
            adjacency.setdefault(edge.producer, []).append(edge)
        result: list[ApiSequence] = []

        def walk(nodes: tuple[str, ...], bindings: tuple[DependencyEdge, ...]) -> None:
            current = nodes[-1]
            if len(nodes) >= 2:
                result.append(ApiSequence(nodes, bindings))
            if len(nodes) == max_depth:
                return
            for edge in adjacency.get(current, []):
                if edge.consumer not in nodes:
                    walk((*nodes, edge.consumer), (*bindings, edge))

        for operation in operations:
            walk((operation.operation_id,), ())
        return sorted(result, key=lambda item: item.operations)
