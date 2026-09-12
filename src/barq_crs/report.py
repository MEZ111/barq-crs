from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from .fusion import RankedCandidate


def _inline(value: object) -> str:
    return (
        str(value)
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("|", "\\|")
        .replace("`", "'")
    )


def markdown_report(items: Iterable[RankedCandidate], campaign: str) -> str:
    ranked = list(items)
    lines = [
        f"# BARQ-CRS Evidence Report — {_inline(campaign)}",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
        "> Candidates are evidence-ranked hypotheses, not confirmed vulnerabilities. Validate only within written authorization.",
        "",
        f"## Queue ({len(ranked)})",
        "",
        "| Priority | Severity | Engine | Candidate | Target |",
        "|---:|---|---|---|---|",
    ]
    for item in ranked:
        finding = item.candidate
        lines.append(
            f"| {item.priority_score:.2f} | {_inline(finding.severity)} | "
            f"{_inline(finding.engine)} | `{_inline(finding.id)}` | "
            f"`{_inline(finding.target)}` |"
        )
    for index, item in enumerate(ranked, 1):
        finding = item.candidate
        lines.extend([
            "", f"## {index}. {_inline(finding.title)}", "",
            f"- ID: `{_inline(finding.id)}`",
            f"- Target: `{_inline(finding.target)}`",
            f"- Priority: **{item.priority_score:.2f}/10**",
            f"- Corroboration: {_inline(', '.join(item.corroborating_engines))}",
            f"- Safe next step: {_inline(finding.safe_next_step)}",
            f"- Remediation direction: {_inline(finding.remediation_hint)}",
            "", "Evidence:", "",
        ])
        for evidence in finding.evidence:
            lines.append(
                f"- `{_inline(evidence.kind)}` — {_inline(evidence.summary)} "
                f"(`{evidence.fingerprint[:16]}`)"
            )
    lines.extend(
        [
            "",
            "## Integrity note",
            "",
            "Raw credentials, cookies, and response bodies are intentionally "
            "excluded from this report.",
            "",
        ]
    )
    return "\n".join(lines)
