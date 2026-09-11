from __future__ import annotations

import argparse
import json
from pathlib import Path

from .authz import AuthorizationDifferentialEngine
from .ctf import ChallengeTriage, FlagOracle
from .drift import ContractDriftEngine
from .fusion import SignalFusion
from .ledger import EvidenceLedger
from .models import Candidate, Evidence, Observation
from .race import StateCollisionEngine, StateTransition
from .report import markdown_report
from .sarif import sarif_report
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
