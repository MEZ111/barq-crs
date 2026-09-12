from __future__ import annotations

from hashlib import sha256
import json
from typing import Any, Iterable, Mapping

from .models import Candidate, Evidence


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
SENSITIVE_TERMS = {
    "admin",
    "token",
    "secret",
    "user",
    "users",
    "account",
    "accounts",
    "payment",
    "payments",
    "billing",
    "export",
    "internal",
    "permission",
    "permissions",
}
Requirement = tuple[tuple[str, tuple[str, ...]], ...]


def _effective_security(document: Mapping[str, Any], operation: Mapping[str, Any]) -> Any:
    return operation["security"] if "security" in operation else document.get("security")


def _fp(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(data.encode()).hexdigest()


def _operations(document: Mapping[str, Any]) -> dict[tuple[str, str], Mapping[str, Any]]:
    result: dict[tuple[str, str], Mapping[str, Any]] = {}
    paths = document.get("paths", {})
    if not isinstance(paths, Mapping):
        raise ValueError("OpenAPI paths must be an object")
    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, Mapping):
            continue
        for method, operation in path_item.items():
            if str(method).lower() in HTTP_METHODS and isinstance(operation, Mapping):
                result[(str(method).upper(), path)] = operation
    return result


def _normalize_requirement(requirement: Mapping[str, Any]) -> Requirement:
    normalized: list[tuple[str, tuple[str, ...]]] = []
    for scheme, scopes in requirement.items():
        if not isinstance(scheme, str):
            raise ValueError("security scheme names must be strings")
        if scopes is None:
            scope_values: tuple[str, ...] = ()
        elif isinstance(scopes, list) and all(isinstance(scope, str) for scope in scopes):
            scope_values = tuple(sorted(set(scopes)))
        else:
            raise ValueError(f"security scopes for {scheme} must be an array of strings")
        normalized.append((scheme, scope_values))
    return tuple(sorted(normalized))


def _normalize_security(value: Any) -> tuple[Requirement, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("security must be an array")
    normalized: set[Requirement] = set()
    for requirement in value:
        if not isinstance(requirement, Mapping):
            raise ValueError("each security requirement must be an object")
        normalized.add(_normalize_requirement(requirement))
    return tuple(sorted(normalized))


def _secured(value: Any) -> bool:
    normalized = _normalize_security(value)
    return bool(normalized) and all(bool(requirement) for requirement in normalized)


def _requirement_map(requirement: Requirement) -> dict[str, set[str]]:
    return {scheme: set(scopes) for scheme, scopes in requirement}


def _weaker_or_equal(candidate: Requirement, baseline: Requirement) -> bool:
    if not candidate:
        return True
    candidate_map = _requirement_map(candidate)
    baseline_map = _requirement_map(baseline)
    if not set(candidate_map).issubset(baseline_map):
        return False
    return all(candidate_map[name].issubset(baseline_map[name]) for name in candidate_map)


def _strictly_weaker(candidate: Requirement, baseline: Requirement) -> bool:
    return candidate != baseline and _weaker_or_equal(candidate, baseline)


def _sensitive(path: str) -> bool:
    terms = {
        part.lower()
        for part in path.replace("{", "/").replace("}", "/").replace("-", "/").replace("_", "/").split("/")
        if part
    }
    return bool(terms & SENSITIVE_TERMS)


def _scheme_definitions(document: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    components = document.get("components", {})
    if isinstance(components, Mapping):
        schemes = components.get("securitySchemes", {})
        if isinstance(schemes, Mapping):
            return {
                str(name): value
                for name, value in schemes.items()
                if isinstance(value, Mapping)
            }
    legacy = document.get("securityDefinitions", {})
    if isinstance(legacy, Mapping):
        return {
            str(name): value
            for name, value in legacy.items()
            if isinstance(value, Mapping)
        }
    return {}


def _candidate(
    *,
    kind: str,
    title: str,
    target: str,
    severity: str,
    confidence: float,
    impact: float,
    summary: str,
    before: Any,
    after: Any,
    remediation: str,
) -> Candidate:
    evidence_value = {"before_security": before, "after_security": after}
    return Candidate(
        engine="contract-drift",
        kind=kind,
        title=title,
        target=target,
        severity=severity,
        confidence=confidence,
        impact=impact,
        novelty=0.94,
        reproducibility=1.0,
        evidence=(
            Evidence(
                kind="openapi-authorization-diff",
                summary=summary,
                fingerprint=_fp([kind, target, evidence_value]),
                metadata={**evidence_value, "verification_strength": "contract"},
            ),
        ),
        remediation_hint=remediation,
        safe_next_step="Review the contract change, then confirm with one non-mutating request in the written program scope.",
    )


class ContractDriftEngine:
    """Detect weakening OpenAPI authorization semantics without flattening OR/AND rules."""

    def analyze(self, before: dict[str, Any], after: dict[str, Any]) -> list[Candidate]:
        old_ops = _operations(before)
        new_ops = _operations(after)
        findings: list[Candidate] = []

        for key in sorted(old_ops.keys() & new_ops.keys()):
            method, path = key
            target = f"{method} {path}"
            previous_security = _effective_security(before, old_ops[key])
            current_security = _effective_security(after, new_ops[key])
            if _secured(previous_security) and not _secured(current_security):
                findings.append(
                    _candidate(
                        kind="authentication-removed",
                        title="API operation lost its effective authentication requirement",
                        target=target,
                        severity="critical" if _sensitive(path) else "high",
                        confidence=0.99,
                        impact=0.98,
                        summary="Authenticated operation became anonymous under effective OpenAPI security semantics",
                        before=previous_security,
                        after=current_security,
                        remediation="Restore an explicit authentication requirement and enforce it server-side.",
                    )
                )
                continue
            if not (_secured(previous_security) and _secured(current_security)):
                continue
            findings.extend(
                self._weakened_requirements(
                    target,
                    path,
                    previous_security,
                    current_security,
                )
            )

        for method, path in sorted(new_ops.keys() - old_ops.keys()):
            operation = new_ops[(method, path)]
            security = _effective_security(after, operation)
            if not _sensitive(path) or _secured(security):
                continue
            findings.append(
                _candidate(
                    kind="new-sensitive-anonymous-operation",
                    title="New sensitive API operation is anonymous",
                    target=f"{method} {path}",
                    severity="critical",
                    confidence=0.96,
                    impact=0.94,
                    summary="A newly introduced sensitive route has no effective authentication requirement",
                    before=None,
                    after=security,
                    remediation="Require authentication and least-privilege authorization before exposing the operation.",
                )
            )

        old_schemes = _scheme_definitions(before)
        new_schemes = _scheme_definitions(after)
        for scheme in sorted(set(old_schemes) - set(new_schemes)):
            findings.append(
                _candidate(
                    kind="security-scheme-definition-removed",
                    title=f"Security scheme definition removed: {scheme}",
                    target="components.securitySchemes",
                    severity="high",
                    confidence=0.98,
                    impact=0.8,
                    summary="A security scheme definition disappeared from the API contract",
                    before={scheme: old_schemes[scheme]},
                    after=None,
                    remediation="Restore the scheme definition or migrate every operation to an explicitly reviewed replacement.",
                )
            )
        for scheme in sorted(set(old_schemes) & set(new_schemes)):
            old_type = old_schemes[scheme].get("type")
            new_type = new_schemes[scheme].get("type")
            if old_type == new_type:
                continue
            findings.append(
                _candidate(
                    kind="security-scheme-type-changed",
                    title=f"Security scheme type changed: {scheme}",
                    target="components.securitySchemes",
                    severity="medium",
                    confidence=0.9,
                    impact=0.65,
                    summary="Authentication mechanism type changed and needs explicit security review",
                    before={"name": scheme, "type": old_type},
                    after={"name": scheme, "type": new_type},
                    remediation="Review runtime enforcement and migration behavior for the changed authentication mechanism.",
                )
            )

        unique = {item.id: item for item in findings}
        return sorted(unique.values(), key=lambda item: (-item.score, item.target, item.kind))

    def _weakened_requirements(
        self,
        target: str,
        path: str,
        previous_security: Any,
        current_security: Any,
    ) -> Iterable[Candidate]:
        old = _normalize_security(previous_security)
        new = _normalize_security(current_security)
        old_set = set(old)
        new_set = set(new)
        for candidate_requirement in sorted(new_set - old_set):
            baselines = [
                baseline
                for baseline in old
                if _strictly_weaker(candidate_requirement, baseline)
            ]
            if not baselines:
                continue
            baseline = min(baselines, key=lambda item: (len(item), item))
            before_map = _requirement_map(baseline)
            after_map = _requirement_map(candidate_requirement)
            old_preserved = baseline in new_set
            removed_schemes = sorted(set(before_map) - set(after_map))
            removed_scopes = {
                scheme: sorted(before_map[scheme] - after_map.get(scheme, set()))
                for scheme in sorted(set(before_map) & set(after_map))
                if before_map[scheme] - after_map.get(scheme, set())
            }
            severity = "critical" if _sensitive(path) else "high"
            if old_preserved:
                yield _candidate(
                    kind="weaker-security-alternative-added",
                    title="A weaker OR authorization alternative was added",
                    target=target,
                    severity=severity,
                    confidence=0.99,
                    impact=0.9,
                    summary="OpenAPI security array entries are OR alternatives; the new alternative is easier to satisfy",
                    before=baseline,
                    after=candidate_requirement,
                    remediation="Remove the weaker alternative or make it enforce the same intended authorization boundary.",
                )
            elif removed_schemes:
                yield _candidate(
                    kind="required-security-scheme-removed",
                    title="An AND security requirement lost a required scheme",
                    target=target,
                    severity=severity,
                    confidence=0.99,
                    impact=0.88,
                    summary="Schemes within one Security Requirement are ANDed; removing one weakens the alternative",
                    before=baseline,
                    after=candidate_requirement,
                    remediation="Restore the removed scheme requirement or explicitly review the weaker authentication path.",
                )
            elif removed_scopes:
                yield _candidate(
                    kind="required-scope-removed",
                    title="Required authorization scopes were removed",
                    target=target,
                    severity=severity,
                    confidence=0.99,
                    impact=0.88,
                    summary="The same authentication alternative now requires fewer declared scopes",
                    before=baseline,
                    after=candidate_requirement,
                    remediation="Restore the removed scopes or verify that the runtime authorization policy was intentionally relaxed.",
                )
