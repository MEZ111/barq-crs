from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
from typing import Any


def stable_id(*parts: object, prefix: str = "barq") -> str:
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return f"{prefix}-{sha256(canonical.encode()).hexdigest()[:16]}"


@dataclass(frozen=True, slots=True)
class Observation:
    timestamp: str
    method: str
    url: str
    route: str
    principal: str
    role: str
    status: int
    body: Any = None
    resource_id: str | None = None
    owns_resource: bool | None = None
    principal_tenant: str | None = None
    resource_tenant: str | None = None
    latency_ms: float | None = None
    tags: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Observation":
        return cls(
            timestamp=str(value.get("timestamp", "")),
            method=str(value.get("method", "GET")).upper(),
            url=str(value["url"]),
            route=str(value.get("route") or value["url"]),
            principal=str(value.get("principal", "anonymous")),
            role=str(value.get("role", "anonymous")),
            status=int(value.get("status", 0)),
            body=value.get("body"),
            resource_id=(str(value["resource_id"]) if value.get("resource_id") is not None else None),
            owns_resource=value.get("owns_resource"),
            principal_tenant=value.get("principal_tenant"),
            resource_tenant=value.get("resource_tenant"),
            latency_ms=(float(value["latency_ms"]) if value.get("latency_ms") is not None else None),
            tags=tuple(str(x) for x in value.get("tags", [])),
        )


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: str
    summary: str
    fingerprint: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(frozen=True, slots=True)
class Candidate:
    engine: str
    kind: str
    title: str
    target: str
    severity: str
    confidence: float
    impact: float
    novelty: float
    reproducibility: float
    evidence: tuple[Evidence, ...]
    remediation_hint: str
    safe_next_step: str
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            object.__setattr__(
                self,
                "id",
                stable_id(self.engine, self.kind, self.target, [e.fingerprint for e in self.evidence]),
            )

    @property
    def score(self) -> float:
        raw = (
            self.confidence * 0.35
            + self.impact * 0.30
            + self.novelty * 0.15
            + self.reproducibility * 0.20
        )
        return round(raw * 10, 2)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["score"] = self.score
        return value


@dataclass(frozen=True, slots=True)
class ProbePlan:
    candidate_id: str
    target: str
    method: str
    purpose: str
    principal_pair: tuple[str, str] | None
    destructive: bool = False
    requires_human_approval: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
