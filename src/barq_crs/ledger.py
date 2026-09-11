from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable


ZERO_HASH = "0" * 64
SECRET_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): ("[REDACTED]" if str(key).lower() in SECRET_KEYS else redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    sequence: int
    kind: str
    timestamp: str
    payload: Any
    previous_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EvidenceLedger:
    """Append-only, hash-chained evidence with secret redaction."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def entries(self) -> list[LedgerEntry]:
        if not self.path.exists():
            return []
        result = []
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    result.append(LedgerEntry(**json.loads(line)))
        return result

    def append(self, kind: str, timestamp: str, payload: Any) -> LedgerEntry:
        previous = self.entries()
        sequence = len(previous) + 1
        previous_hash = previous[-1].entry_hash if previous else ZERO_HASH
        clean_payload = redact(payload)
        material = {
            "sequence": sequence,
            "kind": kind,
            "timestamp": timestamp,
            "payload": clean_payload,
            "previous_hash": previous_hash,
        }
        entry_hash = sha256(canonical_json(material).encode()).hexdigest()
        entry = LedgerEntry(entry_hash=entry_hash, **material)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(entry.to_dict()) + "\n")
        return entry

    def verify(self) -> tuple[bool, str]:
        previous_hash = ZERO_HASH
        expected_sequence = 1
        try:
            entries: Iterable[LedgerEntry] = self.entries()
            for entry in entries:
                if entry.sequence != expected_sequence:
                    return False, f"sequence gap at {expected_sequence}"
                material = {
                    "sequence": entry.sequence,
                    "kind": entry.kind,
                    "timestamp": entry.timestamp,
                    "payload": entry.payload,
                    "previous_hash": entry.previous_hash,
                }
                expected_hash = sha256(canonical_json(material).encode()).hexdigest()
                if entry.previous_hash != previous_hash or entry.entry_hash != expected_hash:
                    return False, f"integrity failure at entry {entry.sequence}"
                previous_hash = entry.entry_hash
                expected_sequence += 1
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return False, f"invalid ledger: {exc}"
        return True, f"verified {expected_sequence - 1} entries"
