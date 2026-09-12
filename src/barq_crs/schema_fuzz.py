from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re
from typing import Any, Iterable


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
READ_METHODS = {"GET", "HEAD", "OPTIONS"}
OBJECT_ID = re.compile(r"(?:^|_)(?:id|uuid|key)$|(?:Id|ID|Uuid|UUID)$")
PRIVILEGED_FIELD = re.compile(
    r"(?:^|_)(?:admin|role|roles|permission|permissions|owner|owner_id|tenant|tenant_id|"
    r"account_id|status|balance|price|credit|verified|is_admin)(?:$|_)",
    re.I,
)


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
            return value
        value = node
    return value


def _stable_id(*parts: object) -> str:
    value = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return "case-" + sha256(value.encode()).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class SchemaMutation:
    location: str
    field: str
    strategy: str
    value_shape: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SchemaTestCase:
    id: str
    operation_id: str
    method: str
    path: str
    category: str
    risk: str
    mutations: tuple[SchemaMutation, ...]
    oracle: str
    preconditions: tuple[str, ...]
    isolated_only: bool
    requires_human_approval: bool

    def to_dict(self) -> dict:
        value = asdict(self)
        value["mutations"] = [mutation.to_dict() for mutation in self.mutations]
        return value


class OpenApiTestPlanner:
    """Builds deterministic, bounded API test plans without sending requests."""

    def plan(self, document: dict[str, Any], *, max_cases: int = 250) -> list[SchemaTestCase]:
        if max_cases < 1 or max_cases > 2_000:
            raise ValueError("max_cases must be between 1 and 2000")
        cases: list[SchemaTestCase] = []
        global_security = document.get("security")
        paths = document.get("paths", {})
        if not isinstance(paths, dict):
            raise ValueError("OpenAPI paths must be an object")
        for path, path_item in sorted(paths.items()):
            if not isinstance(path_item, dict):
                continue
            shared = path_item.get("parameters", [])
            if not isinstance(shared, list):
                shared = []
            for method, operation in sorted(path_item.items()):
                if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                    continue
                upper = method.upper()
                operation_id = str(operation.get("operationId") or f"{method}_{self._slug(path)}")
                security = operation["security"] if "security" in operation else global_security
                authenticated = security not in (None, []) and not (
                    isinstance(security, list) and {} in security
                )
                operation_parameters = operation.get("parameters", [])
                if not isinstance(operation_parameters, list):
                    operation_parameters = []
                parameters = [*shared, *operation_parameters]
                cases.extend(
                    self._operation_cases(
                        document,
                        operation_id,
                        upper,
                        path,
                        operation,
                        parameters,
                        authenticated,
                    )
                )
                if len(cases) >= max_cases:
                    return self._deduplicate(cases)[:max_cases]
        return self._deduplicate(cases)[:max_cases]

    def _operation_cases(
        self,
        document: dict[str, Any],
        operation_id: str,
        method: str,
        path: str,
        operation: dict[str, Any],
        parameters: Iterable[Any],
        authenticated: bool,
    ) -> list[SchemaTestCase]:
        cases: list[SchemaTestCase] = []
        isolated = method not in READ_METHODS
        if authenticated:
            cases.append(
                self._case(
                    operation_id,
                    method,
                    path,
                    "authorization-differential",
                    "high",
                    (SchemaMutation("identity", "session", "controlled-principal-swap", "owner/non-owner/anonymous"),),
                    "Non-owner and anonymous responses reject access without returning protected fields; owner behavior remains stable.",
                    ("Two researcher-controlled identities", "One object owned by the first identity"),
                    isolated,
                )
            )

        resolved_parameters = []
        for raw in parameters:
            parameter = _resolve(document, raw)
            if isinstance(parameter, dict):
                resolved_parameters.append(parameter)
                cases.extend(
                    self._parameter_cases(
                        document, operation_id, method, path, parameter, isolated
                    )
                )

        path_fields = {str(item.get("name", "")) for item in resolved_parameters if item.get("in") == "path"}
        path_fields.update(re.findall(r"\{([^}]+)\}", path))
        for field in sorted(path_fields):
            if self._object_identifier(field):
                cases.append(
                    self._case(
                        operation_id,
                        method,
                        path,
                        "object-boundary-swap",
                        "critical",
                        (SchemaMutation("path", field, "controlled-foreign-object", "same-type identifier"),),
                        "The foreign object is rejected with 403/404 and no protected fields or side effects are returned.",
                        ("Two researcher-controlled identities", "One same-type object per identity"),
                        isolated,
                    )
                )

        body_schema = self._request_schema(document, operation, resolved_parameters)
        if isinstance(body_schema, dict):
            cases.extend(
                self._body_cases(
                    document, operation_id, method, path, body_schema, isolated
                )
            )

        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            cases.append(
                self._case(
                    operation_id,
                    method,
                    path,
                    "state-replay-consistency",
                    "high",
                    (SchemaMutation("request", "request", "controlled-replay", "identical benign request"),),
                    "A repeated or retried request preserves the documented invariant and never duplicates a one-time state change.",
                    ("Isolated disposable fixture", "Known initial resource state"),
                    True,
                )
            )
        return cases

    def _parameter_cases(
        self,
        document: dict[str, Any],
        operation_id: str,
        method: str,
        path: str,
        parameter: dict[str, Any],
        isolated: bool,
    ) -> list[SchemaTestCase]:
        name = str(parameter.get("name", "parameter"))
        location = str(parameter.get("in", "query"))
        schema = _resolve(document, parameter.get("schema", parameter))
        result: list[SchemaTestCase] = []
        if location == "query":
            result.append(
                self._case(
                    operation_id,
                    method,
                    path,
                    "http-parameter-pollution",
                    "medium",
                    (SchemaMutation(location, name, "duplicate-key", "two benign distinct values"),),
                    "Duplicate values are rejected or resolved consistently across gateway, cache, and application layers.",
                    ("Baseline request with one valid value",),
                    isolated,
                )
            )
        result.extend(
            self._schema_boundary_cases(
                operation_id, method, path, location, name, schema, isolated
            )
        )
        return result

    def _body_cases(
        self,
        document: dict[str, Any],
        operation_id: str,
        method: str,
        path: str,
        schema: dict[str, Any],
        isolated: bool,
    ) -> list[SchemaTestCase]:
        schema = _resolve(document, schema)
        result: list[SchemaTestCase] = []
        properties = self._properties(document, schema)
        if properties:
            result.append(
                self._case(
                    operation_id,
                    method,
                    path,
                    "undeclared-property-handling",
                    "medium",
                    (SchemaMutation("body", "__barq_probe", "unknown-property", "benign marker"),),
                    "The server rejects or ignores undeclared input and never persists it into a privileged model field.",
                    ("Disposable object",),
                    isolated,
                )
            )
        for name, child in sorted(properties.items()):
            child = _resolve(document, child)
            if not isinstance(child, dict):
                continue
            if child.get("readOnly") is True or PRIVILEGED_FIELD.search(name):
                result.append(
                    self._case(
                        operation_id,
                        method,
                        path,
                        "mass-assignment-boundary",
                        "critical" if PRIVILEGED_FIELD.search(name) else "high",
                        (SchemaMutation("body", name, "privileged-field-injection", "schema-valid controlled value"),),
                        "The server ignores or rejects the field and the persisted object retains its server-authoritative value.",
                        ("Disposable object", "Read-back through an authorized account"),
                        True,
                    )
                )
            if self._object_identifier(name):
                result.append(
                    self._case(
                        operation_id,
                        method,
                        path,
                        "foreign-object-binding",
                        "high",
                        (SchemaMutation("body", name, "controlled-foreign-object", "same-type identifier"),),
                        "The request cannot bind an object owned by another controlled identity or tenant.",
                        ("Two researcher-controlled identities", "One same-type object per identity"),
                        True,
                    )
                )
            result.extend(
                self._schema_boundary_cases(
                    operation_id, method, path, "body", name, child, isolated
                )
            )
        return result

    def _schema_boundary_cases(
        self,
        operation_id: str,
        method: str,
        path: str,
        location: str,
        field: str,
        schema: Any,
        isolated: bool,
    ) -> list[SchemaTestCase]:
        if not isinstance(schema, dict):
            return []
        result: list[SchemaTestCase] = []
        kind = schema.get("type")
        if kind == "string":
            try:
                maximum = max(0, int(schema.get("maxLength", 256)))
            except (TypeError, ValueError):
                maximum = 256
            shape = f"length {min(maximum + 1, 4097)}"
            result.append(
                self._case(
                    operation_id,
                    method,
                    path,
                    "string-boundary",
                    "medium",
                    (SchemaMutation(location, field, "above-declared-maximum", shape),),
                    "The boundary is rejected deterministically without truncation, parser divergence, or server error.",
                    ("Valid baseline value",),
                    isolated,
                )
            )
            if schema.get("format") in {"uri", "url", "hostname"}:
                result.append(
                    self._case(
                        operation_id,
                        method,
                        path,
                        "canonicalization-differential",
                        "high",
                        (SchemaMutation(location, field, "equivalent-representation", "normalized and alternate benign URI forms"),),
                        "Validation, authorization, caching, and downstream consumers agree on one canonical value.",
                        ("Researcher-controlled destination when a callback is expected",),
                        isolated,
                    )
                )
        elif kind in {"integer", "number"}:
            shapes = ["-1", "0"]
            if "minimum" in schema:
                shapes.append("minimum minus one")
            if "maximum" in schema:
                shapes.append("maximum plus one")
            result.append(
                self._case(
                    operation_id,
                    method,
                    path,
                    "numeric-boundary",
                    "medium",
                    (SchemaMutation(location, field, "numeric-boundaries", ", ".join(dict.fromkeys(shapes))),),
                    "Every out-of-range value is rejected without wraparound, sign confusion, or inconsistent persistence.",
                    ("Valid baseline value",),
                    isolated,
                )
            )
        if kind in {"string", "integer", "number", "boolean"}:
            result.append(
                self._case(
                    operation_id,
                    method,
                    path,
                    "type-confusion",
                    "high",
                    (SchemaMutation(location, field, "type-substitution", "array then object"),),
                    "Every layer rejects the alternate type consistently without authorization or validation bypass.",
                    ("Valid baseline request",),
                    isolated,
                )
            )
        return result

    @staticmethod
    def _request_schema(
        document: dict[str, Any],
        operation: dict[str, Any],
        parameters: Iterable[dict[str, Any]],
    ) -> dict[str, Any] | None:
        request_body = _resolve(document, operation.get("requestBody"))
        if isinstance(request_body, dict):
            content = request_body.get("content", {})
            if not isinstance(content, dict):
                content = {}
            for media_type in ("application/json", "application/*+json"):
                media = content.get(media_type)
                if isinstance(media, dict):
                    schema = _resolve(document, media.get("schema"))
                    if isinstance(schema, dict):
                        return schema
            for media in content.values():
                if isinstance(media, dict):
                    schema = _resolve(document, media.get("schema"))
                    if isinstance(schema, dict):
                        return schema
        for parameter in parameters:
            if parameter.get("in") == "body":
                schema = _resolve(document, parameter.get("schema"))
                if isinstance(schema, dict):
                    return schema
        return None

    @staticmethod
    def _properties(
        document: dict[str, Any],
        schema: dict[str, Any],
        *,
        depth: int = 0,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if depth > 8:
            return result
        schema = _resolve(document, schema)
        if not isinstance(schema, dict):
            return result
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            result.update(properties)
        children = schema.get("allOf", [])
        if not isinstance(children, list):
            children = []
        for child in children:
            resolved = _resolve(document, child)
            if isinstance(resolved, dict):
                result.update(
                    OpenApiTestPlanner._properties(
                        document, resolved, depth=depth + 1
                    )
                )
        return result

    @staticmethod
    def _object_identifier(value: str) -> bool:
        normalized = re.sub(r"[^A-Za-z0-9_]", "_", value)
        return bool(OBJECT_ID.search(normalized))

    @staticmethod
    def _slug(value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()

    @staticmethod
    def _case(
        operation_id: str,
        method: str,
        path: str,
        category: str,
        risk: str,
        mutations: tuple[SchemaMutation, ...],
        oracle: str,
        preconditions: tuple[str, ...],
        isolated_only: bool,
    ) -> SchemaTestCase:
        identifier = _stable_id(
            operation_id,
            method,
            path,
            category,
            [mutation.to_dict() for mutation in mutations],
        )
        return SchemaTestCase(
            identifier,
            operation_id,
            method,
            path,
            category,
            risk,
            mutations,
            oracle,
            preconditions,
            isolated_only,
            True,
        )

    @staticmethod
    def _deduplicate(cases: Iterable[SchemaTestCase]) -> list[SchemaTestCase]:
        unique = {case.id: case for case in cases}
        return sorted(unique.values(), key=lambda case: (case.operation_id, case.category, case.id))
