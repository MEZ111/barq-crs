from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from .authz import AuthorizationDifferentialEngine
from .api_graph import OpenApiDependencyGraph
from .campaign import CampaignRunner
from .collector import EvidenceCollector, RequestSpec, SessionProfile
from .ctf import ChallengeTriage, FlagOracle
from .drift import ContractDriftEngine
from .fusion import SignalFusion
from .ledger import EvidenceLedger
from .mobile import AndroidArtifactAnalyzer
from .models import Candidate, Evidence, Observation
from .race import StateCollisionEngine, StateTransition
from .report import markdown_report
from .sarif import sarif_report
from .schema_fuzz import OpenApiTestPlanner
from .scope import ScopePolicy
from .traffic import BurpXmlIngestor, HarIngestor
from .variant import PatchSeededVariantEngine


def _json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _jsonl(path: str):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def _candidate(value: dict) -> Candidate:
    value = dict(value)
    value.pop("score", None)
    value["evidence"] = tuple(Evidence(**item) for item in value.get("evidence", []))
    return Candidate(**value)


def _emit(value) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def _emit_jsonl(values) -> None:
    for value in values:
        print(json.dumps(value, separators=(",", ":"), ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="barq", description="Evidence-gated reasoning for authorized security research")
    commands = parser.add_subparsers(dest="command", required=True)
    authz = commands.add_parser("authz", help="analyze controlled-identity response observations")
    authz.add_argument("observations")
    drift = commands.add_parser("drift", help="compare two OpenAPI documents")
    drift.add_argument("before"); drift.add_argument("after")
    variants = commands.add_parser("variants", help="mine source siblings from a security patch")
    variants.add_argument("diff"); variants.add_argument("root")
    race = commands.add_parser("collisions", help="model candidate state-transition collisions")
    race.add_argument("transitions")
    triage = commands.add_parser("ctf-triage", help="classify an isolated challenge directory")
    triage.add_argument("root")
    flag = commands.add_parser("flag-check", help="apply a local flag oracle to a text file")
    flag.add_argument("file")
    collect = commands.add_parser(
        "collect",
        help="collect a bounded read-only identity matrix from an authorized scope",
    )
    collect.add_argument("policy")
    collect.add_argument("requests")
    collect.add_argument("profiles")
    har = commands.add_parser("ingest-har", help="convert HAR traffic to BARQ JSONL")
    har.add_argument("file")
    har.add_argument("--principal", required=True)
    har.add_argument("--role", default="user")
    har.add_argument("--tenant")
    burp = commands.add_parser(
        "ingest-burp",
        help="convert a Burp Suite XML history export to BARQ JSONL",
    )
    burp.add_argument("file")
    burp.add_argument("--principal", required=True)
    burp.add_argument("--role", default="user")
    burp.add_argument("--tenant")
    graph = commands.add_parser(
        "api-sequences",
        help="infer stateful producer/consumer sequences from OpenAPI",
    )
    graph.add_argument("spec")
    graph.add_argument("--depth", type=int, default=3)
    api_plan = commands.add_parser(
        "api-plan",
        help="generate bounded authorization, state, and schema test cases from OpenAPI",
    )
    api_plan.add_argument("spec")
    api_plan.add_argument("--max-cases", type=int, default=250)
    mobile = commands.add_parser(
        "mobile",
        help="statically analyze an APK/ZIP or decoded Android directory",
    )
    mobile.add_argument("artifact")
    hunt = commands.add_parser(
        "hunt",
        help="run a complete local campaign and emit report, SARIF, plans, and ledger",
    )
    hunt.add_argument("campaign")
    hunt.add_argument("--output", default="barq-output")
    rank = commands.add_parser("rank", help="rank a JSON list of BARQ candidates")
    rank.add_argument("candidates"); rank.add_argument("--report"); rank.add_argument("--campaign", default="authorized-research")
    sarif = commands.add_parser("sarif", help="convert BARQ candidates to SARIF 2.1.0")
    sarif.add_argument("candidates"); sarif.add_argument("output")
    verify = commands.add_parser("ledger-verify", help="verify an evidence ledger hash chain")
    verify.add_argument("ledger")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "authz":
        findings = AuthorizationDifferentialEngine().analyze(Observation.from_dict(x) for x in _jsonl(args.observations))
        _emit([item.to_dict() for item in findings])
    elif args.command == "drift":
        findings = ContractDriftEngine().analyze(_json(args.before), _json(args.after))
        _emit([item.to_dict() for item in findings])
    elif args.command == "variants":
        findings = PatchSeededVariantEngine().analyze(Path(args.diff).read_text(encoding="utf-8"), args.root)
        _emit([item.to_dict() for item in findings])
    elif args.command == "collisions":
        findings = StateCollisionEngine().analyze(StateTransition.from_dict(x) for x in _json(args.transitions))
        _emit([item.to_dict() for item in findings])
    elif args.command == "ctf-triage":
        _emit([item.to_dict() for item in ChallengeTriage().analyze(args.root)])
    elif args.command == "flag-check":
        _emit(list(FlagOracle().find(Path(args.file).read_text(encoding="utf-8", errors="ignore"))))
    elif args.command == "collect":
        policy = ScopePolicy.load(args.policy)
        requests = [RequestSpec.from_dict(value) for value in _json(args.requests)]
        profiles = [SessionProfile.from_env_dict(value) for value in _json(args.profiles)]
        observations = EvidenceCollector(policy).collect_matrix(requests, profiles)
        _emit_jsonl(asdict(observation) for observation in observations)
    elif args.command == "ingest-har":
        observations = HarIngestor().load(
            args.file,
            principal=args.principal,
            role=args.role,
            tenant=args.tenant,
        )
        _emit_jsonl(asdict(observation) for observation in observations)
    elif args.command == "ingest-burp":
        observations = BurpXmlIngestor().load(
            args.file,
            principal=args.principal,
            role=args.role,
            tenant=args.tenant,
        )
        _emit_jsonl(asdict(observation) for observation in observations)
    elif args.command == "api-sequences":
        engine = OpenApiDependencyGraph()
        document = _json(args.spec)
        operations = engine.operations(document)
        sequences = engine.sequences(document, max_depth=args.depth)
        _emit(
            {
                "operations": [operation.to_dict() for operation in operations],
                "sequences": [sequence.to_dict() for sequence in sequences],
            }
        )
    elif args.command == "api-plan":
        cases = OpenApiTestPlanner().plan(_json(args.spec), max_cases=args.max_cases)
        _emit([case.to_dict() for case in cases])
    elif args.command == "mobile":
        _emit(AndroidArtifactAnalyzer().analyze(args.artifact).to_dict())
    elif args.command == "hunt":
        _emit(CampaignRunner().run(args.campaign, args.output).to_dict())
    elif args.command == "rank":
        ranked = SignalFusion().rank(_candidate(x) for x in _json(args.candidates))
        if args.report:
            Path(args.report).write_text(markdown_report(ranked, args.campaign), encoding="utf-8")
        _emit([item.to_dict() for item in ranked])
    elif args.command == "sarif":
        value = sarif_report(_candidate(x) for x in _json(args.candidates))
        Path(args.output).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        _emit({"written": args.output, "results": len(value["runs"][0]["results"])})
    elif args.command == "ledger-verify":
        valid, message = EvidenceLedger(args.ledger).verify()
        _emit({"valid": valid, "message": message})
        return 0 if valid else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
