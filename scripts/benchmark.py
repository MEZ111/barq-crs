from __future__ import annotations

import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from barq_crs.authz import AuthorizationDifferentialEngine
from barq_crs.api_graph import OpenApiDependencyGraph
from barq_crs.campaign import CampaignRunner
from barq_crs.drift import ContractDriftEngine
from barq_crs.ledger import EvidenceLedger
from barq_crs.mobile import AndroidArtifactAnalyzer
from barq_crs.models import Observation
from barq_crs.race import StateCollisionEngine, StateTransition
from barq_crs.schema_fuzz import OpenApiTestPlanner
from barq_crs.traffic import BurpXmlIngestor, HarIngestor
from barq_crs.variant import PatchSeededVariantEngine


DEMO = ROOT / "examples" / "demo"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    observations = [Observation.from_dict(json.loads(line)) for line in (DEMO / "observations.jsonl").read_text().splitlines()]
    stateful_openapi = load(DEMO / "stateful-openapi.json")
    mobile = AndroidArtifactAnalyzer().analyze(DEMO / "mobile-app")
    with TemporaryDirectory(prefix="barq-benchmark-") as output_directory:
        campaign = CampaignRunner().run(
            DEMO / "hunt-campaign.json", output_directory
        )
        ledger_valid, _ = EvidenceLedger(campaign.artifacts["ledger"]).verify()
    results = {
        "authorization": len(AuthorizationDifferentialEngine().analyze(observations)),
        "contract_drift": len(ContractDriftEngine().analyze(load(DEMO / "openapi-before.json"), load(DEMO / "openapi-after.json"))),
        "patch_variants": len(PatchSeededVariantEngine().analyze((DEMO / "security-fix.diff").read_text(), DEMO / "source")),
        "state_collisions": len(StateCollisionEngine().analyze(StateTransition.from_dict(x) for x in load(DEMO / "transitions.json"))),
        "har_observations": len(
            HarIngestor().load(
                DEMO / "traffic-owner.har", principal="owner", role="user"
            )
        ),
        "burp_observations": len(
            BurpXmlIngestor().load(
                DEMO / "burp-owner.xml", principal="owner", role="user"
            )
        ),
        "api_sequences": len(
            OpenApiDependencyGraph().sequences(
                stateful_openapi, max_depth=3
            )
        ),
        "schema_test_cases": len(OpenApiTestPlanner().plan(stateful_openapi)),
        "mobile_candidates": len(mobile.candidates),
        "campaign_candidates": campaign.candidate_count,
        "campaign_artifacts": len(campaign.artifacts),
        "ledger_valid": ledger_valid,
    }
    expected = {
        "authorization": 3,
        "contract_drift": 2,
        "patch_variants": 1,
        "state_collisions": 1,
        "har_observations": 1,
        "burp_observations": 1,
        "api_sequences": 1,
        "schema_test_cases": 7,
        "mobile_candidates": 11,
        "campaign_candidates": 18,
        "campaign_artifacts": 6,
        "ledger_valid": True,
    }
    output = {"fixture": "barq-ground-truth-v2", "counts": results, "expected": expected, "passed": results == expected}
    print(json.dumps(output, indent=2))
    return 0 if output["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
