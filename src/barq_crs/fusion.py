from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Iterable

from .models import Candidate


def _normal_target(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


@dataclass(frozen=True, slots=True)
class RankedCandidate:
    candidate: Candidate
    corroborating_engines: tuple[str, ...]
    target_signal_count: int
    priority_score: float

    def to_dict(self) -> dict:
        value = asdict(self)
        value["candidate"] = self.candidate.to_dict()
        return value


class SignalFusion:
    """Deduplicates candidates and rewards independent evidence on one target."""

    def rank(self, candidates: Iterable[Candidate]) -> list[RankedCandidate]:
        unique = {candidate.id: candidate for candidate in candidates}
        by_target: dict[str, list[Candidate]] = {}
        for candidate in unique.values():
            by_target.setdefault(_normal_target(candidate.target), []).append(candidate)

        ranked = []
        for candidate in unique.values():
            peers = by_target[_normal_target(candidate.target)]
            engines = tuple(sorted({peer.engine for peer in peers}))
            evidence_count = sum(len(peer.evidence) for peer in peers)
            corroboration_bonus = min(1.2, 0.45 * max(0, len(engines) - 1))
            evidence_bonus = min(0.6, 0.12 * max(0, evidence_count - 1))
            priority = min(10.0, candidate.score + corroboration_bonus + evidence_bonus)
            ranked.append(
                RankedCandidate(
                    candidate=candidate,
                    corroborating_engines=engines,
                    target_signal_count=len(peers),
                    priority_score=round(priority, 2),
                )
            )
        return sorted(
            ranked,
            key=lambda item: (-item.priority_score, item.candidate.id),
        )
