from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
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
}
PRIVILEGED_ROLES = {"admin", "owner", "superadmin", "staff", "manager"}


def _json_fingerprint(value: Any) -> str:
    material = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(material.encode()).hexdigest()


def _keys(value: Any, prefix: str = "") -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            result.add(path)
            result.add(str(key))
            result.update(_keys(child, path))
    elif isinstance(value, list):
        for child in value[:5]:
            result.update(_keys(child, prefix + "[]"))
    return result


def _sensitive_keys(value: Any, configured: set[str]) -> set[str]:
    return {key for key in _keys(value) if key.rsplit(".", 1)[-1].replace("[]", "") in configured}


def _success(status: int) -> bool:
    return 200 <= status < 300


class AuthorizationDifferentialEngine:
    """Finds evidence-backed authorization divergence across controlled identities."""

    def __init__(self, sensitive_keys: Iterable[str] = DEFAULT_SENSITIVE_KEYS):
        self.sensitive_keys = {str(key).lower() for key in sensitive_keys}

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
        return findings
    def _anonymous_exposure(self, target: str, samples: list[Observation]) -> list[Candidate]:
        findings = []
        for obs in samples:
            if obs.role != "anonymous" or not _success(obs.status):
                continue
            sensitive = _sensitive_keys(obs.body, self.sensitive_keys)
            if not sensitive:
                continue
            fp = _json_fingerprint(obs.body)
            findings.append(
                Candidate(
                    engine="authorization-differential",
                    kind="anonymous-sensitive-response",
                    title="Anonymous principal received a sensitive response",
                    target=target,
                    severity="critical" if len(sensitive) >= 3 else "high",
                    confidence=0.94,
                    impact=min(1.0, 0.72 + len(sensitive) * 0.05),
                    novelty=0.72,
                    reproducibility=0.9,
                    evidence=(
                        Evidence(
                            kind="response-shape",
                            summary="Unauthenticated 2xx response contains sensitive fields",
                            fingerprint=fp,
                            metadata={"status": obs.status, "sensitive_keys": sorted(sensitive)},
                        ),
                    ),
                    remediation_hint="Require authentication and object-level authorization before serialization.",
                    safe_next_step="Repeat one read-only request with and without a session; compare only owned test data.",
                )
            )
        return findings

    def _object_access(self, target: str, samples: list[Observation]) -> list[Candidate]:
        owners = [x for x in samples if x.owns_resource is True and _success(x.status)]
        nonowners = [x for x in samples if x.owns_resource is False and _success(x.status)]
        findings = []
        for owner in owners:
            owner_fp = _json_fingerprint(owner.body)
            owner_sensitive = _sensitive_keys(owner.body, self.sensitive_keys)
            for viewer in nonowners:
                viewer_fp = _json_fingerprint(viewer.body)
                overlap = owner_sensitive & _sensitive_keys(viewer.body, self.sensitive_keys)
                if not overlap:
                    continue
                exact = owner_fp == viewer_fp
                confidence = 0.97 if exact else min(0.92, 0.68 + 0.05 * len(overlap))
                findings.append(
                    Candidate(
                        engine="authorization-differential",
                        kind="cross-principal-object-access",
                        title="Non-owner received protected object data",
                        target=target,
                        severity="critical" if exact and len(overlap) >= 2 else "high",
                        confidence=confidence,
                        impact=min(1.0, 0.75 + 0.04 * len(overlap)),
                        novelty=0.88,
                        reproducibility=0.95,
                        evidence=(
                            Evidence(
                                kind="principal-differential",
                                summary="Owner and non-owner received overlapping sensitive object data",
                                fingerprint=_json_fingerprint([owner_fp, viewer_fp, sorted(overlap)]),
                                metadata={
                                    "owner": owner.principal,
                                    "viewer": viewer.principal,
                                    "same_response": exact,
                                    "sensitive_keys": sorted(overlap),
                                },
                            ),
                        ),
                        remediation_hint="Authorize the requested object against the authenticated principal and tenant.",
                        safe_next_step="Confirm once using two researcher-controlled accounts and a harmless owned object.",
                    )
                )
        return findings

    def _role_parity(self, target: str, samples: list[Observation]) -> list[Candidate]:
        privileged = [x for x in samples if x.role.lower() in PRIVILEGED_ROLES and _success(x.status)]
        ordinary = [
            x
            for x in samples
            if x.role.lower() not in PRIVILEGED_ROLES | {"anonymous"} and _success(x.status)
        ]
        findings = []
        for admin in privileged:
            admin_keys = _keys(admin.body)
            if not admin_keys:
                continue
            for user in ordinary:
                user_keys = _keys(user.body)
                parity = len(admin_keys & user_keys) / len(admin_keys)
                privileged_route = any(term in target.lower() for term in ("admin", "manage", "internal"))
                if parity < 0.8 or not privileged_route:
                    continue
                findings.append(
                    Candidate(
                        engine="authorization-differential",
                        kind="role-response-parity",
                        title="Low-privilege response mirrors a privileged route",
                        target=target,
                        severity="high",
                        confidence=min(0.95, parity),
                        impact=0.82,
                        novelty=0.82,
                        reproducibility=0.88,
                        evidence=(
                            Evidence(
                                kind="schema-parity",
                                summary=f"Response field parity is {parity:.0%}",
                                fingerprint=_json_fingerprint([target, admin.role, user.role, round(parity, 3)]),
                                metadata={"privileged_role": admin.role, "viewer_role": user.role, "parity": parity},
                            ),
                        ),
                        remediation_hint="Enforce function-level authorization before executing privileged handlers.",
                        safe_next_step="Verify the route with a low-privilege test account without changing state.",
                    )
                )
        return findings

    def _tenant_crossing(self, target: str, samples: list[Observation]) -> list[Candidate]:
        findings = []
        for obs in samples:
            if (
                _success(obs.status)
                and obs.principal_tenant
                and obs.resource_tenant
                and obs.principal_tenant != obs.resource_tenant
            ):
                findings.append(
                    Candidate(
                        engine="authorization-differential",
                        kind="cross-tenant-access",
                        title="Principal crossed a tenant boundary",
                        target=target,
                        severity="critical",
                        confidence=0.98,
                        impact=0.98,
                        novelty=0.9,
                        reproducibility=0.92,
                        evidence=(
                            Evidence(
                                kind="tenant-boundary",
                                summary="Successful response references a different controlled tenant",
                                fingerprint=_json_fingerprint(
                                    [target, obs.principal_tenant, obs.resource_tenant, obs.status]
                                ),
                                metadata={
                                    "principal_tenant": obs.principal_tenant,
                                    "resource_tenant": obs.resource_tenant,
                                    "status": obs.status,
                                },
                            ),
                        ),
                        remediation_hint="Bind every object lookup to the authenticated tenant identifier.",
                        safe_next_step="Recheck with two researcher-controlled tenants and a read-only object.",
                    )
                )
        return findings
