from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from barq_crs.authz import AuthorizationDifferentialEngine
from barq_crs.drift import ContractDriftEngine
from barq_crs.models import Observation
from barq_crs.race import StateCollisionEngine, StateTransition
from barq_crs.variant import PatchSeededVariantEngine


DEMO = ROOT / "examples" / "demo"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    observations = [Observation.from_dict(json.loads(line)) for line in (DEMO / "observations.jsonl").read_text().splitlines()]
    results = {
        "authorization": len(AuthorizationDifferentialEngine().analyze(observations)),
        "contract_drift": len(ContractDriftEngine().analyze(load(DEMO / "openapi-before.json"), load(DEMO / "openapi-after.json"))),
        "patch_variants": len(PatchSeededVariantEngine().analyze((DEMO / "security-fix.diff").read_text(), DEMO / "source")),
        "state_collisions": len(StateCollisionEngine().analyze(StateTransition.from_dict(x) for x in load(DEMO / "transitions.json"))),
    }
    expected = {"authorization": 3, "contract_drift": 2, "patch_variants": 1, "state_collisions": 1}
    output = {"fixture": "barq-ground-truth-v1", "counts": results, "expected": expected, "passed": results == expected}
    print(json.dumps(output, indent=2))
    return 0 if output["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
