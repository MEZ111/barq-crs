from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Callable

from .api_graph import ApiSequence, OpenApiDependencyGraph
from .authz import AuthorizationDifferentialEngine
from .collector import (
    CollectorLimits,
    EvidenceCollector,
    RequestSpec,
    SessionProfile,
)
from .drift import ContractDriftEngine
from .fusion import RankedCandidate, SignalFusion
from .ledger import EvidenceLedger
from .mobile import AndroidArtifactAnalyzer, MobileInventory
from .models import Candidate, Observation
from .race import StateCollisionEngine, StateTransition
from .report import markdown_report
from .sarif import sarif_report
from .schema_fuzz import OpenApiTestPlanner, SchemaTestCase
from .scope import ScopePolicy
from .variant import PatchSeededVariantEngine


@dataclass(frozen=True, slots=True)
class CampaignResult:
    campaign: str
    output_directory: str
    candidate_count: int
    high_or_critical_count: int
    schema_test_count: int
    api_sequence_count: int
    observation_count: int
    mobile_file_count: int
    artifacts: dict[str, str]
    top_candidates: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["top_candidates"] = list(self.top_candidates)
        return value


class CampaignRunner:
    """Runs BARQ's local engines as one reproducible, evidence-gated campaign."""

    def __init__(
        self,
        *,
        mobile_analyzer: AndroidArtifactAnalyzer | None = None,
        schema_planner: OpenApiTestPlanner | None = None,
        collector_factory: Callable[[ScopePolicy, CollectorLimits], EvidenceCollector] | None = None,
    ):
        self.mobile_analyzer = mobile_analyzer or AndroidArtifactAnalyzer()
        self.schema_planner = schema_planner or OpenApiTestPlanner()
        self.collector_factory = collector_factory or (
            lambda policy, limits: EvidenceCollector(policy, limits)
        )

    def run(self, manifest_path: str | Path, output_directory: str | Path) -> CampaignResult:
        manifest_file = Path(manifest_path).resolve()
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("campaign manifest must contain a JSON object")
        base = manifest_file.parent
        inputs = manifest.get("inputs", {})
        if not isinstance(inputs, dict) or not inputs:
            raise ValueError("campaign manifest requires a non-empty inputs object")
        limits = manifest.get("limits", {})
        if not isinstance(limits, dict):
            raise ValueError("campaign limits must be an object")
        campaign = str(manifest.get("name") or manifest_file.stem)
        candidates: list[Candidate] = []
        observations: list[Observation] = []
        schema_cases: list[SchemaTestCase] = []
        api_sequences: list[ApiSequence] = []
        mobile_inventory: MobileInventory | None = None

        if "observations" in inputs:
            observations.extend(
                Observation.from_dict(json.loads(line))
                for line in self._input(base, inputs["observations"]).read_text(encoding="utf-8").splitlines()
                if line.strip()
            )

        if "collection" in inputs:
            collection = inputs["collection"]
            if not isinstance(collection, dict):
                raise ValueError("collection input must be an object")
            required = {"policy", "requests", "profiles"}
            missing = required - collection.keys()
            if missing:
                raise ValueError(
                    "collection input is missing: " + ", ".join(sorted(missing))
                )
            policy = ScopePolicy.load(self._input(base, collection["policy"]))
            requests = [
                RequestSpec.from_dict(value)
                for value in self._json_list(
                    self._input(base, collection["requests"]), "collection.requests"
                )
            ]
            profiles = [
                SessionProfile.from_env_dict(value)
                for value in self._json_list(
                    self._input(base, collection["profiles"]), "collection.profiles"
                )
            ]
            collection_limits = collection.get("limits", {})
            if not isinstance(collection_limits, dict):
                raise ValueError("collection limits must be an object")
            collector_limits = CollectorLimits(
                max_requests=int(collection_limits.get("max_requests", 100)),
                max_body_bytes=int(collection_limits.get("max_body_bytes", 1_000_000)),
                timeout_seconds=float(collection_limits.get("timeout_seconds", 10.0)),
            )
            observations.extend(
                self.collector_factory(policy, collector_limits).collect_matrix(
                    requests, profiles
                )
            )

        if observations:
            candidates.extend(AuthorizationDifferentialEngine().analyze(observations))

        openapi_document: dict[str, Any] | None = None
        if "openapi" in inputs:
            openapi_document = self._json_object(
                self._input(base, inputs["openapi"]), "openapi"
            )
            max_cases = int(limits.get("max_schema_cases", 250))
            depth = int(limits.get("api_sequence_depth", 3))
            schema_cases.extend(self.schema_planner.plan(openapi_document, max_cases=max_cases))
            api_sequences.extend(OpenApiDependencyGraph().sequences(openapi_document, max_depth=depth))

        has_before = "openapi_before" in inputs
        has_after = "openapi_after" in inputs
        if has_before != has_after:
            raise ValueError("openapi_before and openapi_after must be supplied together")
        if has_before:
            candidates.extend(
                ContractDriftEngine().analyze(
                    self._json_object(
                        self._input(base, inputs["openapi_before"]), "openapi_before"
                    ),
                    self._json_object(
                        self._input(base, inputs["openapi_after"]), "openapi_after"
                    ),
                )
            )

        has_patch = "security_patch" in inputs
        has_source = "source_root" in inputs
        if has_patch != has_source:
            raise ValueError("security_patch and source_root must be supplied together")
        if has_patch:
            patch = self._input(base, inputs["security_patch"]).read_text(encoding="utf-8")
            candidates.extend(
                PatchSeededVariantEngine().analyze(
                    patch,
                    self._input(base, inputs["source_root"]),
                )
            )

        if "transitions" in inputs:
            transitions = [
                StateTransition.from_dict(item)
                for item in self._json_list(
                    self._input(base, inputs["transitions"]), "transitions"
                )
            ]
            candidates.extend(StateCollisionEngine().analyze(transitions))

        if "mobile" in inputs:
            mobile = self.mobile_analyzer.analyze(self._input(base, inputs["mobile"]))
            mobile_inventory = mobile.inventory
            candidates.extend(mobile.candidates)

        ranked = SignalFusion().rank(candidates)
        output = Path(output_directory).resolve()
        output.mkdir(parents=True, exist_ok=True)
        generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
        artifact_paths = {
            "report": output / "report.md",
            "candidates": output / "candidates.json",
            "test_plan": output / "test-plan.json",
            "sarif": output / "results.sarif",
            "ledger": output / "evidence-ledger.jsonl",
            "summary": output / "summary.json",
        }

        candidate_values = [item.candidate.to_dict() for item in ranked]
        artifact_paths["report"].write_text(markdown_report(ranked, campaign), encoding="utf-8")
        self._write_json(artifact_paths["candidates"], candidate_values)
        self._write_json(
            artifact_paths["test_plan"],
            {
                "campaign": campaign,
                "generated": generated,
                "schema_tests": [case.to_dict() for case in schema_cases],
                "api_sequences": [sequence.to_dict() for sequence in api_sequences],
                "observation_count": len(observations),
                "mobile_inventory": mobile_inventory.to_dict() if mobile_inventory else None,
            },
        )
        self._write_json(artifact_paths["sarif"], sarif_report(item.candidate for item in ranked))

        # A run owns its ledger file. Rebuilding it avoids silently mixing two
        # campaigns while preserving an append-only hash chain within the run.
        artifact_paths["ledger"].write_text("", encoding="utf-8")
        ledger = EvidenceLedger(artifact_paths["ledger"])
        ledger.append(
            "campaign-start",
            generated,
            {
                "campaign": campaign,
                "schema_test_count": len(schema_cases),
                "api_sequence_count": len(api_sequences),
                "observation_count": len(observations),
            },
        )
        for item in ranked:
            candidate = item.candidate
            ledger.append(
                "candidate",
                generated,
                {
                    "id": candidate.id,
                    "engine": candidate.engine,
                    "kind": candidate.kind,
                    "target": candidate.target,
                    "priority_score": item.priority_score,
                    "evidence_fingerprints": [evidence.fingerprint for evidence in candidate.evidence],
                },
            )
        valid, ledger_message = ledger.verify()
        if not valid:
            raise RuntimeError(ledger_message)

        result = CampaignResult(
            campaign=campaign,
            output_directory=str(output),
            candidate_count=len(ranked),
            high_or_critical_count=sum(
                item.candidate.severity.lower() in {"high", "critical"} for item in ranked
            ),
            schema_test_count=len(schema_cases),
            api_sequence_count=len(api_sequences),
            observation_count=len(observations),
            mobile_file_count=mobile_inventory.file_count if mobile_inventory else 0,
            artifacts={name: str(path) for name, path in artifact_paths.items()},
            top_candidates=tuple(self._top_candidate(item) for item in ranked[:10]),
        )
        self._write_json(
            artifact_paths["summary"],
            {**result.to_dict(), "generated": generated, "ledger": ledger_message},
        )
        return result

    @staticmethod
    def _top_candidate(item: RankedCandidate) -> dict[str, Any]:
        return {
            "id": item.candidate.id,
            "kind": item.candidate.kind,
            "title": item.candidate.title,
            "target": item.candidate.target,
            "severity": item.candidate.severity,
            "priority_score": item.priority_score,
            "engines": list(item.corroborating_engines),
        }

    @staticmethod
    def _input(base: Path, raw: Any) -> Path:
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError("campaign input paths must be non-empty strings")
        candidate = Path(raw)
        resolved = candidate.resolve() if candidate.is_absolute() else (base / candidate).resolve()
        try:
            resolved.relative_to(base)
        except ValueError as exc:
            raise ValueError(f"campaign input escapes its directory: {raw}") from exc
        if not resolved.exists():
            raise FileNotFoundError(resolved)
        return resolved

    @staticmethod
    def _json(path: Path):
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _json_list(path: Path, label: str) -> list[Any]:
        value = CampaignRunner._json(path)
        if not isinstance(value, list):
            raise ValueError(f"{label} must contain a JSON array")
        return value

    @staticmethod
    def _json_object(path: Path, label: str) -> dict[str, Any]:
        value = CampaignRunner._json(path)
        if not isinstance(value, dict):
            raise ValueError(f"{label} must contain a JSON object")
        return value

    @staticmethod
    def _write_json(path: Path, value: Any) -> None:
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
