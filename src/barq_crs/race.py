from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from itertools import combinations
from typing import Iterable

from .models import Candidate, Evidence


@dataclass(frozen=True, slots=True)
class StateTransition:
    route: str
    resource_kind: str
    operation: str
    access: str
    invariant: str

    @classmethod
    def from_dict(cls, value: dict) -> "StateTransition":
        return cls(**{key: str(value[key]) for key in ("route", "resource_kind", "operation", "access", "invariant")})


class StateCollisionEngine:
    """Finds candidate transition collisions without firing concurrent requests."""

    def analyze(self, transitions: Iterable[StateTransition]) -> list[Candidate]:
        findings = []
        for left, right in combinations(transitions, 2):
            if left.resource_kind != right.resource_kind or left.route == right.route:
                continue
            if "write" not in {left.access.lower(), right.access.lower()}:
                continue
            if left.invariant != right.invariant:
                continue
            material = f"{left.route}|{right.route}|{left.resource_kind}|{left.invariant}"
            fingerprint = sha256(material.encode()).hexdigest()
            sensitive = any(word in material.lower() for word in ("balance", "quota", "coupon", "invite", "role"))
            findings.append(
                Candidate(
                    engine="state-collision",
                    kind="shared-invariant-collision",
                    title="Two transitions may race across one business invariant",
                    target=f"{left.route} || {right.route}",
                    severity="high" if sensitive else "medium",
                    confidence=0.61,
                    impact=0.9 if sensitive else 0.68,
                    novelty=0.94,
                    reproducibility=0.56,
                    evidence=(
                        Evidence(
                            "state-machine",
                            "Distinct routes touch the same resource invariant "
                            "and at least one writes",
                            fingerprint,
                            {
                                "left": left.route,
                                "right": right.route,
                                "resource_kind": left.resource_kind,
                                "invariant": left.invariant,
                            },
                        ),
                    ),
                    remediation_hint=(
                        "Serialize invariant checks and mutations in one transaction "
                        "or idempotent state transition."
                    ),
                    safe_next_step=(
                        "Model the collision in an isolated fixture; any live "
                        "verification needs written authorization and human approval."
                    ),
                )
            )
        return findings
