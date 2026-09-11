from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
from typing import Iterable

from .models import Candidate, Evidence


_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_IF_LINE = re.compile(r"^(?:if|elif)\s+(.+?)(?::\s*)$")
_KEYWORDS = {"if", "elif", "for", "while", "return", "raise", "len", "str", "int", "bool"}


@dataclass(frozen=True, slots=True)
class PatchSeed:
    guard_calls: tuple[str, ...]
    guarded_names: tuple[str, ...]
    protected_calls: tuple[str, ...]
    fingerprint: str

    @classmethod
    def from_unified_diff(cls, text: str) -> "PatchSeed":
        added = [line[1:].strip() for line in text.splitlines() if line.startswith("+") and not line.startswith("+++")]
        context = [line[1:].strip() for line in text.splitlines() if line.startswith(" ")]
        guard_calls: set[str] = set()
        guarded_names: set[str] = set()
        for line in added:
            match = _IF_LINE.match(line)
            if not match:
                continue
            expression = match.group(1)
            guard_calls.update(_CALL.findall(expression))
            try:
                tree = ast.parse(expression, mode="eval")
                if any(isinstance(node, (ast.Compare, ast.BoolOp, ast.UnaryOp)) for node in ast.walk(tree)):
                    guarded_names.update(node.id for node in ast.walk(tree) if isinstance(node, ast.Name))
            except SyntaxError:
                guarded_names.update(re.findall(r"\b[A-Za-z_]\w*\b", expression))
        all_added_calls = {call for line in added for call in _CALL.findall(line)}
        context_calls = {call for line in context for call in _CALL.findall(line)}
        protected = (context_calls | all_added_calls) - guard_calls - _KEYWORDS
        fingerprint = sha256(text.encode()).hexdigest()
        return cls(
            guard_calls=tuple(sorted(guard_calls)),
            guarded_names=tuple(sorted(guarded_names - guard_calls - _KEYWORDS)),
            protected_calls=tuple(sorted(protected)),
            fingerprint=fingerprint,
        )


@dataclass(frozen=True, slots=True)
class _Facts:
    name: str
    line: int
    calls: frozenset[str]
    guarded_names: frozenset[str]
    subscript_names: frozenset[str]


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _facts(tree: ast.AST) -> Iterable[_Facts]:
    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        calls = {name for node in ast.walk(function) if isinstance(node, ast.Call) if (name := _call_name(node))}
        guarded: set[str] = set()
        for guard in (node for node in ast.walk(function) if isinstance(node, (ast.If, ast.Assert))):
            test = guard.test
            guarded.update(node.id for node in ast.walk(test) if isinstance(node, ast.Name))
        subscripts: set[str] = set()
        for subscript in (node for node in ast.walk(function) if isinstance(node, ast.Subscript)):
            subscripts.update(node.id for node in ast.walk(subscript.slice) if isinstance(node, ast.Name))
        yield _Facts(function.name, function.lineno, frozenset(calls), frozenset(guarded), frozenset(subscripts))


class PatchSeededVariantEngine:
    """Searches Python siblings for security checks introduced by a trusted patch."""

    def analyze(self, diff_text: str, root: str | Path) -> list[Candidate]:
        seed = PatchSeed.from_unified_diff(diff_text)
        findings: list[Candidate] = []
        root_path = Path(root)
        for path in sorted(root_path.rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue
            for facts in _facts(tree):
                missing_call_guard = (
                    bool(set(seed.protected_calls) & facts.calls)
                    and bool(seed.guard_calls)
                    and not bool(set(seed.guard_calls) & facts.calls)
                )
                missing_index_guard = (
                    bool(set(seed.guarded_names) & facts.subscript_names)
                    and not bool(set(seed.guarded_names) & facts.guarded_names)
                )
                if not (missing_call_guard or missing_index_guard):
                    continue
                relative = str(path.relative_to(root_path))
                pattern = "missing-security-call" if missing_call_guard else "missing-index-guard"
                evidence_meta = {
                    "file": relative,
                    "function": facts.name,
                    "line": facts.line,
                    "patch_guard_calls": list(seed.guard_calls),
                    "patch_guarded_names": list(seed.guarded_names),
                    "patch_fingerprint": seed.fingerprint,
                }
                evidence_fp = sha256(repr(sorted(evidence_meta.items())).encode()).hexdigest()
                findings.append(
                    Candidate(
                        engine="patch-seeded-variant",
                        kind=pattern,
                        title="Sibling code path may be missing a security check introduced by a patch",
                        target=f"{relative}:{facts.line}::{facts.name}",
                        severity="high",
                        confidence=0.78 if missing_call_guard else 0.73,
                        impact=0.84,
                        novelty=0.95,
                        reproducibility=1.0,
                        evidence=(
                            Evidence(
                                "static-variant",
                                "AST structure matches the patched operation "
                                "without its new guard",
                                evidence_fp,
                                evidence_meta,
                            ),
                        ),
                        remediation_hint=(
                            "Apply an equivalent invariant, then add a regression "
                            "test covering the sibling path."
                        ),
                        safe_next_step="Review the source and reproduce only in a local test harness.",
                    )
                )
        return findings
