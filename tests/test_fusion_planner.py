import pytest

from barq_crs.fusion import SignalFusion
from barq_crs.models import Candidate, Evidence
from barq_crs.planner import BoundedBudget, BudgetExhausted, EvidenceGatedPlanner
from barq_crs.scope import ScopePolicy, ScopeViolation


def candidate(engine="one", confidence=.9, method="GET"):
    return Candidate(engine, "auth", "candidate", f"{method} /v1/account", "high", confidence, .9, .8, .9,
                     (Evidence("shape", "evidence", engine),), "fix", "read only")


def test_fusion_rewards_independent_engines():
    ranked = SignalFusion().rank([candidate("one"), candidate("two")])
    assert ranked[0].priority_score > ranked[0].candidate.score
    assert ranked[0].corroborating_engines == ("one", "two")


def test_fusion_deduplicates_identical_id():
    item = candidate()
    assert len(SignalFusion().rank([item, item])) == 1


def planner(max_plans=2):
    policy = ScopePolicy.from_dict({"targets": [{"pattern": "lab.example.test", "methods": ["GET", "POST"]}]})
    return EvidenceGatedPlanner(policy, BoundedBudget(max_plans))


def test_planner_outputs_reviewable_plan():
    plan = planner().plan(candidate(), "https://lab.example.test")
    assert plan.target == "https://lab.example.test/v1/account"
    assert plan.requires_human_approval is True


def test_planner_marks_state_change():
    assert planner().plan(candidate(method="POST"), "https://lab.example.test").destructive is True


def test_planner_rejects_weak_signal():
    with pytest.raises(ScopeViolation, match="evidence"):
        planner().plan(candidate(confidence=.2), "https://lab.example.test")


def test_planner_enforces_budget():
    value = planner(max_plans=1)
    value.plan(candidate(), "https://lab.example.test")
    with pytest.raises(BudgetExhausted):
        value.plan(candidate("two"), "https://lab.example.test")
