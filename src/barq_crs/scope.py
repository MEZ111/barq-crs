from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit, urlunsplit


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
DEFAULT_DENY_TERMS = (
    "delete",
    "destroy",
    "terminate",
    "deactivate",
    "logout",
    "payment",
    "purchase",
    "transfer",
    "withdraw",
)


class ScopeViolation(ValueError):
    """Raised before any task can be planned outside an explicit policy."""


@dataclass(frozen=True, slots=True)
class TargetRule:
    pattern: str
    schemes: tuple[str, ...] = ("https",)
    ports: tuple[int, ...] = (443,)
    methods: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")
    max_rps: float = 1.0

    def matches_host(self, host: str) -> bool:
        host = host.rstrip(".").lower()
        pattern = self.pattern.rstrip(".").lower()
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(host) in network
        except ValueError:
            pass
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return host.endswith("." + suffix) and host != suffix
        return host == pattern


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    name: str
    targets: tuple[TargetRule, ...]
    deny_paths: tuple[str, ...] = ()
    active_testing: bool = False
    human_approval_required: bool = True

    @classmethod
    def from_dict(cls, value: dict) -> "ScopePolicy":
        targets = []
        for item in value.get("targets", []):
            max_rps = float(item.get("max_rps", 1.0))
            if not 0 < max_rps <= 5:
                raise ScopeViolation("max_rps must be greater than 0 and no more than 5")
            targets.append(
                TargetRule(
                    pattern=str(item["pattern"]),
                    schemes=tuple(x.lower() for x in item.get("schemes", ["https"])),
                    ports=tuple(int(x) for x in item.get("ports", [443])),
                    methods=tuple(x.upper() for x in item.get("methods", ["GET", "HEAD", "OPTIONS"])),
                    max_rps=max_rps,
                )
            )
        if not targets:
            raise ScopeViolation("policy must contain at least one explicit target")
        return cls(
            name=str(value.get("name", "unnamed-program")),
            targets=tuple(targets),
            deny_paths=tuple(str(x) for x in value.get("deny_paths", [])),
            active_testing=bool(value.get("active_testing", False)),
            human_approval_required=bool(value.get("human_approval_required", True)),
        )

    @classmethod
    def load(cls, path: str | Path) -> "ScopePolicy":
        with open(path, encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    @property
    def digest(self) -> str:
        canonical = json.dumps(
            {
                "name": self.name,
                "targets": [
                    {
                        "pattern": t.pattern,
                        "schemes": t.schemes,
                        "ports": t.ports,
                        "methods": t.methods,
                        "max_rps": t.max_rps,
                    }
                    for t in self.targets
                ],
                "deny_paths": self.deny_paths,
                "active_testing": self.active_testing,
                "human_approval_required": self.human_approval_required,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(canonical.encode()).hexdigest()

    def authorized_rule(
        self,
        url: str,
        method: str = "GET",
        *,
        active: bool = False,
    ) -> tuple[str, TargetRule]:
        canonical = canonical_url(url)
        parsed = urlsplit(canonical)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        method = method.upper()
        matched = next(
            (
                rule
                for rule in self.targets
                if rule.matches_host(parsed.hostname or "")
                and parsed.scheme in rule.schemes
                and port in rule.ports
                and method in rule.methods
            ),
            None,
        )
        if not matched:
            raise ScopeViolation(f"target is not explicitly authorized: {canonical}")
        decoded_path = unquote(parsed.path).lower()
        denied = tuple(x.lower() for x in self.deny_paths) + DEFAULT_DENY_TERMS
        if any(re.search(rf"(^|[/_-]){re.escape(term)}([/_-]|$)", decoded_path) for term in denied):
            raise ScopeViolation(f"path is blocked by safety policy: {parsed.path}")
        if active and not self.active_testing:
            raise ScopeViolation("active testing is disabled by the program policy")
        if active and method in SAFE_METHODS:
            return canonical, matched
        if active and method not in SAFE_METHODS and self.human_approval_required:
            raise ScopeViolation("state-changing probe requires explicit human approval")
        return canonical, matched

    def authorize(self, url: str, method: str = "GET", *, active: bool = False) -> str:
        canonical, _ = self.authorized_rule(url, method, active=active)
        return canonical


def canonical_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ScopeViolation("only absolute HTTP(S) URLs are accepted")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    port = parsed.port
    default = (parsed.scheme.lower() == "https" and port == 443) or (
        parsed.scheme.lower() == "http" and port == 80
    )
    netloc = host if port is None or default else f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
