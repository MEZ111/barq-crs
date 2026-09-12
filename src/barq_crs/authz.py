from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
import re
from typing import Any, Iterable

from .models import Candidate, Evidence, Observation


DEFAULT_SENSITIVE_KEYS = {
    "email",
    "phone",
    "address",
    "national_id",
    "ssn",
    "iban",
    "balance",
    "salary",
    "token",
    "secret",
    "permissions",
    "roles",
    "tenant_id",
    "user_id",
    "account_id",
    "owner_id",
    "date_of_birth",
    "dob",
}
PRIVILEGED_ROLES = {"admin", "owner", "superadmin", "staff", "manager"}
VOLATILE_KEYS = {
    "timestamp",
    "created_at",
    "updated_at",
    "request_id",
    "requestid",
    "trace_id",
    "traceid",
    "correlation_id",
    "correlationid",
    "nonce",
    "etag",
    "server_time",
    "servertime",
}
DENIAL_TERMS = (
    "unauthorized",
    "forbidden",
    "access denied",
    "permission denied",
    "not allowed",
    "not found",
    "authentication required",
)
DENIAL_KEYS = {"error", "message", "detail", "reason", "code", "status"}


def _normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _is_sensitive_name(value: str, configured: set[str]) -> bool:
    return _normalize_name(value.replace("[]", "")) in configured


def _canonicalize(value: Any, *, depth: int = 0) -> Any:
    """Remove common response noise while preserving security-relevant structure."""
    if depth > 32:
        return "[DEPTH-LIMIT]"
    if isinstance(value, dict):
        return {
            str(key): _canonicalize(child, depth=depth + 1)
            for key, child in sorted(value.items(), key=lambda item: str(item[0]))
            if _normalize_name(str(key)) not in VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [_canonicalize(child, depth=depth + 1) for child in value[:500]]
    if isinstance(value, tuple):
        return [_canonicalize(child, depth=depth + 1) for child in value[:500]]
    return value


def body_fingerprint(value: Any) -> str:
    material = json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        ensure_ascii=False,
    )
    return sha256(material.encode()).hexdigest()


def _json_fingerprint(value: Any) -> str:
    material = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(material.encode()).hexdigest()


def _walk_paths(value: Any, prefix: str = "", *, depth: int = 0) -> list[tuple[str, str, Any]]:
    if depth > 32:
        return []
    result: list[tuple[str, str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            if isinstance(child, (dict, list, tuple)):
                result.extend(_walk_paths(child, path, depth=depth + 1))
            else:
                result.append((path, key_text, child))
    elif isinstance(value, (list, tuple)):
        for child in value[:100]:
            result.extend(_walk_paths(child, prefix + "[]", depth=depth + 1))
    return result


def _keys(value: Any, prefix: str = "", *, depth: int = 0) -> set[str]:
    if depth > 32:
        return set()
    result: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            result.add(path)
            result.add(key_text)
            result.update(_keys(child, path, depth=depth + 1))
    elif isinstance(value, (list, tuple)):
        for child in value[:100]:
            result.update(_keys(child, prefix + "[]", depth=depth + 1))
    return result


def _shape(value: Any, prefix: str = "", *, depth: int = 0) -> set[str]:
    if depth > 32:
        return set()
    result: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            if _normalize_name(key_text) in VOLATILE_KEYS:
                continue
            path = f"{prefix}.{key_text}" if prefix else key_text
            result.add(f"{path}:{type(child).__name__}")
            result.update(_shape(child, path, depth=depth + 1))
    elif isinstance(value, (list, tuple)):
        for child in value[:25]:
            result.update(_shape(child, prefix + "[]", depth=depth + 1))
    return result


def _sensitive_keys(value: Any, configured: set[str]) -> set[str]:
    return {
        path
        for path, key, _ in _walk_paths(value)
        if _is_sensitive_name(key, configured)
    }


def _sensitive_value_hashes(value: Any, configured: set[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for path, key, child in _walk_paths(value):
        if not _is_sensitive_name(key, configured):
            continue
        material = json.dumps(child, sort_keys=True, separators=(",", ":"), default=str)
        result[path] = sha256((path + "\x00" + material).encode()).hexdigest()
    return result


def _success(status: int) -> bool:
    return 200 <= status < 300


def _empty_body(value: Any) -> bool:
    return value is None or value == "" or value == {} or value == []


def _denial_like(value: Any, configured: set[str]) -> bool:
    if _sensitive_keys(value, configured):
        return False
    if not isinstance(value, dict):
        return False
    messages: list[str] = []
    for key, child in value.items():
        if _normalize_name(str(key)) not in DENIAL_KEYS:
            continue
        if isinstance(child, (str, int, float)):
            messages.append(str(child).lower())
    text = " ".join(messages)
    return any(term in text for term in DENIAL_TERMS)


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def response_summary(value: Any, sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS) -> dict[str, Any]:
    configured = {_normalize_name(str(key)) for key in sensitive_keys}
    shape = sorted(_shape(value))
    sensitive = sorted(_sensitive_keys(value, configured))
    return {
        "body_fingerprint": body_fingerprint(value),
        "shape_fingerprint": _json_fingerprint(shape),
        "sensitive_keys": sensitive,
        "empty": _empty_body(value),
        "denial_like": _denial_like(value, configured),
    }


class AuthorizationDifferentialEngine:
    """Find evidence-backed authorization divergence across controlled identities.

    BARQ intentionally favors high-specificity evidence: exact normalized body matches,
    matching sensitive values, or strong shape/sensitivity agreement. Raw response values
    are never copied into findings.
    """

    def __init__(self, sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS):
        self.sensitive_keys = {_normalize_name(str(key)) for key in sensitive_keys}

    def analyze(self, observations: Iterable[Observation]) -> list[Candidate]:
        groups: dict[tuple[str, str, str | None], list[Observation]] = defaultdict(list)
        for obs in observations:
            groups[(obs.method, obs.route, obs.resource_id)].append(obs)

        findings: list[Candidate] = []
        for (method, route, resource_id), samples in groups.items():
            target = f"{method} {route}" + (f" [resource={resource_id}]" if resource_id else "")
            findings.extend(self._anonymous_exposure(target, samples))
            findings.extend(self._object_access(target, samples))
            findings.extend(self._role_parity(target, samples))
            findings.extend(self._tenant_crossing(target, samples))
        unique = {item.id: item for item in findings}
        return sorted(unique.values(), key=lambda item: (-item.score, item.target, item.kind))

    def _usable(self, obs: Observation) -> bool:
        return _success(obs.status) and not _empty_body(obs.body) and not _denial_like(obs.body, self.sensitive_keys)

    def _comparison(self, baseline: Observation, viewer: Observation) -> dict[str, Any]:
        baseline_fp = body_fingerprint(baseline.body)
        viewer_fp = body_fingerprint(viewer.body)
        baseline_values = _sensitive_value_hashes(baseline.body, self.sensitive_keys)
        viewer_values = _sensitive_value_hashes(viewer.body, self.sensitive_keys)
        matching_sensitive = sorted(
            path
            for path, fingerprint in baseline_values.items()
            if viewer_values.get(path) == fingerprint
        )
        baseline_sensitive = _sensitive_keys(baseline.body, self.sensitive_keys)
        viewer_sensitive = _sensitive_keys(viewer.body, self.sensitive_keys)
        sensitive_overlap = sorted(baseline_sensitive & viewer_sensitive)
        shape_similarity = _jaccard(_shape(baseline.body), _shape(viewer.body))
        exact = baseline_fp == viewer_fp and not _empty_body(baseline.body)
        if exact or matching_sensitive:
            strength = "verified"
        elif len(sensitive_overlap) >= 2 and shape_similarity >= 0.85:
            strength = "likely"
        else:
            strength = "insufficient"
        return {
            "exact": exact,
            "matching_sensitive": matching_sensitive,
            "sensitive_overlap": sensitive_overlap,
            "shape_similarity": round(shape_similarity, 4),
            "strength": strength,
            "fingerprint": _json_fingerprint(
                [baseline_fp, viewer_fp, matching_sensitive, sensitive_overlap, round(shape_similarity, 4)]
            ),
        }

    def _anonymous_exposure(self, target: str, samples: list[Observation]) -> list[Candidate]:
        findings: list[Candidate] = []
        baselines = [sample for sample in samples if sample.role.lower() != "anonymous" and self._usable(sample)]
        for obs in samples:
            if obs.role.lower() != "anonymous" or not self._usable(obs):
                continue
            sensitive = sorted(_sensitive_keys(obs.body, self.sensitive_keys))
            if not sensitive:
                continue
            comparisons = [self._comparison(baseline, obs) for baseline in baselines]
            best = next((item for item in comparisons if item["strength"] == "verified"), None)
            strength = "verified" if best else "likely"
            evidence_fp = best["fingerprint"] if best else body_fingerprint(obs.body)
            confidence = 0.99 if strength == "verified" else 0.91
            findings.append(
                Candidate(
                    engine="authorization-differential",
                    kind="anonymous-sensitive-response",
                    title="Anonymous principal received protected response data",
                    target=target,
                    severity="critical" if strength == "verified" or len(sensitive) >= 3 else "high",
                    confidence=confidence,
                    impact=min(1.0, 0.78 + len(sensitive) * 0.04),
                    novelty=0.78,
                    reproducibility=0.94,
                    evidence=(
                        Evidence(
                            kind="anonymous-differential",
                            summary="Unauthenticated 2xx response contains sensitive fields",
                            fingerprint=evidence_fp,
                            metadata={
                                "status": obs.status,
                                "sensitive_keys": sensitive,
                                "verification_strength": strength,
                                "matches_authenticated_baseline": bool(best),
                            },
                        ),
                    ),
                    remediation_hint="Require authentication and object-level authorization before serialization.",
                    safe_next_step="Repeat one read-only request with and without a researcher-controlled session.",
                )
            )
        return findings

    def _object_access(self, target: str, samples: list[Observation]) -> list[Candidate]:
        owners = [sample for sample in samples if sample.owns_resource is True and self._usable(sample)]
        nonowners = [sample for sample in samples if sample.owns_resource is False and self._usable(sample)]
        findings: list[Candidate] = []
        for owner in owners:
            for viewer in nonowners:
                comparison = self._comparison(owner, viewer)
                if comparison["strength"] == "insufficient":
                    continue
                verified = comparison["strength"] == "verified"
                findings.append(
                    Candidate(
                        engine="authorization-differential",
                        kind="cross-principal-object-access",
                        title="Non-owner received another controlled principal's object",
                        target=target,
                        severity="critical" if verified else "high",
                        confidence=0.99 if comparison["exact"] else (0.97 if verified else 0.84),
                        impact=0.98 if verified else 0.86,
                        novelty=0.9,
                        reproducibility=0.97,
                        evidence=(
                            Evidence(
                                kind="principal-differential",
                                summary=(
                                    "Owner and non-owner responses match protected values"
                                    if verified
                                    else "Owner and non-owner responses have strong protected-data parity"
                                ),
                                fingerprint=comparison["fingerprint"],
                                metadata={
                                    "owner": owner.principal,
                                    "viewer": viewer.principal,
                                    "owner_status": owner.status,
                                    "viewer_status": viewer.status,
                                    "same_response": comparison["exact"],
                                    "matching_sensitive_keys": comparison["matching_sensitive"],
                                    "sensitive_key_overlap": comparison["sensitive_overlap"],
                                    "shape_similarity": comparison["shape_similarity"],
                                    "verification_strength": comparison["strength"],
                                },
                            ),
                        ),
                        remediation_hint="Bind the requested object to the authenticated principal and tenant before serialization.",
                        safe_next_step="Confirm once with the same two researcher-controlled accounts and object alias.",
                    )
                )
        return findings

    def _role_parity(self, target: str, samples: list[Observation]) -> list[Candidate]:
        if not any(term in target.lower() for term in ("admin", "manage", "internal", "staff")):
            return []
        privileged = [
            sample
            for sample in samples
            if sample.role.lower() in PRIVILEGED_ROLES and self._usable(sample)
        ]
        ordinary = [
            sample
            for sample in samples
            if sample.role.lower() not in PRIVILEGED_ROLES | {"anonymous"} and self._usable(sample)
        ]
        findings: list[Candidate] = []
        for admin in privileged:
            for user in ordinary:
                comparison = self._comparison(admin, user)
                user_sensitive = _sensitive_keys(user.body, self.sensitive_keys)
                if comparison["strength"] == "insufficient" or not user_sensitive:
                    continue
                verified = comparison["strength"] == "verified"
                findings.append(
                    Candidate(
                        engine="authorization-differential",
                        kind="role-response-parity",
                        title="Low-privilege identity mirrors a privileged route",
                        target=target,
                        severity="critical" if verified and comparison["exact"] else "high",
                        confidence=0.97 if verified else 0.84,
                        impact=0.9,
                        novelty=0.84,
                        reproducibility=0.93,
                        evidence=(
                            Evidence(
                                kind="role-differential",
                                summary="Low-privilege response substantially matches privileged protected data",
                                fingerprint=comparison["fingerprint"],
                                metadata={
                                    "privileged_role": admin.role,
                                    "viewer_role": user.role,
                                    "same_response": comparison["exact"],
                                    "matching_sensitive_keys": comparison["matching_sensitive"],
                                    "shape_similarity": comparison["shape_similarity"],
                                    "verification_strength": comparison["strength"],
                                },
                            ),
                        ),
                        remediation_hint="Enforce function-level authorization before executing privileged handlers.",
                        safe_next_step="Recheck the read-only route with the same controlled low-privilege identity.",
                    )
                )
        return findings

    def _tenant_crossing(self, target: str, samples: list[Observation]) -> list[Candidate]:
        owners = [sample for sample in samples if sample.owns_resource is True and self._usable(sample)]
        findings: list[Candidate] = []
        for viewer in samples:
            if not (
                viewer.owns_resource is False
                and self._usable(viewer)
                and viewer.principal_tenant
                and viewer.resource_tenant
                and viewer.principal_tenant != viewer.resource_tenant
            ):
                continue
            best: dict[str, Any] | None = None
            for owner in owners:
                comparison = self._comparison(owner, viewer)
                if comparison["strength"] == "verified":
                    best = comparison
                    break
                if comparison["strength"] == "likely" and best is None:
                    best = comparison
            sensitive = sorted(_sensitive_keys(viewer.body, self.sensitive_keys))
            if best is None and not sensitive:
                continue
            strength = best["strength"] if best else "likely"
            findings.append(
                Candidate(
                    engine="authorization-differential",
                    kind="cross-tenant-access",
                    title="Controlled identity received data from another tenant",
                    target=target,
                    severity="critical" if strength == "verified" else "high",
                    confidence=0.99 if strength == "verified" else 0.88,
                    impact=0.99,
                    novelty=0.92,
                    reproducibility=0.95,
                    evidence=(
                        Evidence(
                            kind="tenant-differential",
                            summary="Successful read crossed an explicitly modeled tenant boundary",
                            fingerprint=(
                                best["fingerprint"]
                                if best
                                else _json_fingerprint(
                                    [target, viewer.principal_tenant, viewer.resource_tenant, viewer.status, sensitive]
                                )
                            ),
                            metadata={
                                "viewer": viewer.principal,
                                "principal_tenant": viewer.principal_tenant,
                                "resource_tenant": viewer.resource_tenant,
                                "status": viewer.status,
                                "sensitive_keys": sensitive,
                                "verification_strength": strength,
                                "matches_owner_baseline": bool(best and best["strength"] == "verified"),
                            },
                        ),
                    ),
                    remediation_hint="Bind every object lookup to the authenticated tenant identifier.",
                    safe_next_step="Confirm once using the same two researcher-controlled tenants and read-only object.",
                )
            )
        return findings
