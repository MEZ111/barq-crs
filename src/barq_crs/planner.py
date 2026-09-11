from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin
import re

from .models import Candidate, ProbePlan
from .scope import SAFE_METHODS, ScopePolicy, ScopeViolation


class BudgetExhausted(RuntimeError):
    pass


@dataclass(slots=True)
class BoundedBudget:
    max_plans: int = 20
    used: int = 0

    def reserve(self) -> None:
        if self.used >= self.max_plans:
            raise BudgetExhausted(f"plan budget exhausted ({self.max_plans})")
        self.used += 1


def _extract_method_path(target: str) -> tuple[str, str]:
    match = re.match(r"^(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\s+([^\s]+)", target, re.I)
    if not match:
        return "GET", target.split(" [", 1)[0]
    return match.group(1).upper(), match.group(2)


class EvidenceGatedPlanner:
    """Creates reviewable plans; it deliberately never sends network traffic."""

    def __init__(self, policy: ScopePolicy, budget: BoundedBudget | None = None):
        self.policy = policy
        self.budget = budget or BoundedBudget()

    def plan(self, candidate: Candidate, base_url: str) -> ProbePlan:
        if candidate.confidence < 0.55 or not candidate.evidence:
            raise ScopeViolation("candidate lacks sufficient evidence for planning")
        method, path = _extract_method_path(candidate.target)
        target = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        # Scope is checked in analysis mode. Execution remains an explicit human step.
        canonical = self.policy.authorize(target, method, active=False)
        self.budget.reserve()
        state_changing = method not in SAFE_METHODS
        return ProbePlan(
            candidate_id=candidate.id,
            target=canonical,
            method=method,
            purpose=candidate.safe_next_step,
            principal_pair=("controlled-owner", "controlled-reviewer")
            if "principal" in candidate.kind or "tenant" in candidate.kind
            else None,
            destructive=state_changing,
            requires_human_approval=True,
        )
