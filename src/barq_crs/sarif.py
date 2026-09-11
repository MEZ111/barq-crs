from __future__ import annotations

import re
from typing import Iterable

from .models import Candidate


_SOURCE_TARGET = re.compile(r"^(?P<path>.+\.py):(?P<line>\d+)::")
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def sarif_report(candidates: Iterable[Candidate]) -> dict:
    findings = list(candidates)
    rules: dict[str, dict] = {}
    results = []
    for candidate in findings:
        rule_id = f"barq/{candidate.engine}/{candidate.kind}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": candidate.kind.replace("-", "_")[:128],
                "shortDescription": {"text": candidate.title},
                "help": {"text": candidate.remediation_hint},
                "properties": {"precision": "medium", "security-severity": f"{candidate.score:.1f}"},
            },
        )
        result = {
            "ruleId": rule_id,
            "level": _LEVEL.get(candidate.severity.lower(), "warning"),
            "message": {"text": f"{candidate.title}. {candidate.safe_next_step}"},
            "partialFingerprints": {"barqCandidateId": candidate.id},
            "properties": {
                "barq_score": candidate.score,
                "engine": candidate.engine,
                "evidence_fingerprints": [evidence.fingerprint for evidence in candidate.evidence],
            },
        }
        match = _SOURCE_TARGET.match(candidate.target)
        if match:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": match.group("path")},
                    "region": {"startLine": int(match.group("line"))},
                }
            }]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "BARQ-CRS",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/MEZ111/barq-crs",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
