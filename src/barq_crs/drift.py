from __future__ import annotations

from hashlib import sha256
import json
from typing import Any

from .models import Candidate, Evidence


SENSITIVE_TERMS = {"admin", "token", "secret", "user", "account", "payment", "export", "internal"}


def _effective_security(document: dict[str, Any], operation: dict[str, Any]) -> Any:
    return operation["security"] if "security" in operation else document.get("security")


def _anonymous(security: Any) -> bool:
    return security is None or security == [] or (isinstance(security, list) and {} in security)


def _fp(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(data.encode()).hexdigest()


def _operations(document: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result = {}
    for path, path_item in document.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"} and isinstance(operation, dict):
                result[(method.upper(), path)] = operation
    return result


class ContractDriftEngine:
    def analyze(self, before: dict[str, Any], after: dict[str, Any]) -> list[Candidate]:
        old_ops = _operations(before)
        new_ops = _operations(after)
        findings = []
        for key, operation in new_ops.items():
            method, path = key
            current_security = _effective_security(after, operation)
            previous = old_ops.get(key)
            # An OpenAPI operation is allowed to be an empty object. Treat only
            # a missing key as absent; truthiness would lose inherited security.
            previous_security = _effective_security(before, previous) if previous is not None else None
            terms = {part.lower() for part in path.replace("{", "/").replace("}", "/").split("/") if part}
            sensitive = bool(terms & SENSITIVE_TERMS)
            kind = None
            title = None
            confidence = 0.0
            impact = 0.0
            if previous is not None and not _anonymous(previous_security) and _anonymous(current_security):
                kind = "authentication-removed"
                title = "API operation lost its effective authentication requirement"
                confidence, impact = 0.98, 0.95
            elif previous is None and _anonymous(current_security) and sensitive:
                kind = "new-sensitive-anonymous-operation"
                title = "New sensitive API operation is anonymous"
                confidence, impact = 0.93, 0.9
            if not kind:
                continue
            target = f"{method} {path}"
            evidence_value = {
                "before_security": previous_security,
                "after_security": current_security,
                "new_operation": previous is None,
            }
            findings.append(
                Candidate(
                    engine="contract-drift",
                    kind=kind,
                    title=title,
                    target=target,
                    severity="critical" if sensitive else "high",
                    confidence=confidence,
                    impact=impact,
                    novelty=0.94,
                    reproducibility=1.0,
                    evidence=(
                        Evidence(
                            kind="openapi-diff",
                            summary="Effective security changed across two versioned contracts",
                            fingerprint=_fp(evidence_value),
                            metadata=evidence_value,
                        ),
                    ),
                    remediation_hint="Restore an explicit security requirement and enforce it server-side.",
                    safe_next_step="Confirm contract ownership and make one non-mutating request without credentials.",
                )
            )
        return findings
