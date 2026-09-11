from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re


SIGNALS = {
    "web": {"http", "cookie", "flask", "django", "express", "html", "jwt", "graphql"},
    "pwn": {"elf", "libc", "overflow", "rop", "pwntools", "canary", "binary"},
    "reverse": {"apk", "dex", "decompile", "ghidra", "ida", "wasm", "bytecode"},
    "crypto": {"rsa", "aes", "nonce", "cipher", "modulus", "prime", "xor"},
    "forensics": {"pcap", "memory", "disk", "exif", "steganography", "wireshark", "volatility"},
    "cloud": {"iam", "s3", "bucket", "kubernetes", "docker", "metadata", "terraform"},
}
EXTENSIONS = {
    ".pcap": "forensics", ".pcapng": "forensics", ".apk": "reverse", ".dex": "reverse",
    ".wasm": "reverse", ".so": "pwn", ".elf": "pwn", ".pem": "crypto", ".tf": "cloud",
    ".html": "web", ".js": "web",
}


@dataclass(frozen=True, slots=True)
class TriageResult:
    category: str
    score: int
    signals: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


class ChallengeTriage:
    def analyze(self, root: str | Path) -> list[TriageResult]:
        root_path = Path(root)
        scores = {category: 0 for category in SIGNALS}
        evidence: dict[str, set[str]] = {category: set() for category in SIGNALS}
        for path in sorted(root_path.rglob("*")):
            if not path.is_file():
                continue
            category = EXTENSIONS.get(path.suffix.lower())
            if category:
                scores[category] += 3
                evidence[category].add(f"extension:{path.suffix.lower()}")
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")[:100_000].lower()
            except OSError:
                continue
            haystack = f"{path.name.lower()} {text}"
            for candidate, words in SIGNALS.items():
                hits = {word for word in words if word in haystack}
                scores[candidate] += len(hits)
                evidence[candidate].update(hits)
        return sorted(
            (TriageResult(category, score, tuple(sorted(evidence[category]))) for category, score in scores.items() if score),
            key=lambda result: (-result.score, result.category),
        )


class FlagOracle:
    def __init__(self, pattern: str = r"(?:flag|ctf|picoCTF)\{[^}\n]{1,200}\}"):
        self.pattern = re.compile(pattern, re.I)

    def find(self, text: str) -> tuple[str, ...]:
        return tuple(dict.fromkeys(match.group(0) for match in self.pattern.finditer(text)))
