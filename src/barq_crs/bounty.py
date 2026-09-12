from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .scope import ScopePolicy
from .verifier import VerificationRunner


class BountyError(ValueError):
    """Raised before a bounty campaign can leave its explicit authorization envelope."""


@dataclass(frozen=True, slots=True)
class BountyLead:
    id: str
    kind: str
    url: str
    route: str
    score: int
    confidence: str
    source: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class BountyResult:
    campaign: str
    domain: str
    output_directory: str
    recon_run: str
    lead_count: int
    verified_count: int
    scanner_signal_count: int
    new_lead_count: int
    artifacts: dict[str, str]
    top_leads: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["top_leads"] = list(self.top_leads)
        return value


class EndpointPrioritizer:
    """Collapse noisy recon URLs into a small, high-value review queue.

    This is deliberately a prioritizer, not an exploit engine. It looks for surfaces
    associated with common high-impact bug classes and deduplicates URL variants by
    route shape so a researcher reviews the useful edge instead of thousands of clones.
    """

    _ID_VALUE = re.compile(
        r"^(?:\d{2,}|[0-9a-f]{16,}|[0-9a-f]{8}(?:-[0-9a-f]{4}){2,}-[0-9a-f]{8,}|[A-Za-z0-9_-]{20,})$",
        re.IGNORECASE,
    )
    _OBJECT_WORDS = frozenset(
        {
            "user",
            "users",
            "account",
            "accounts",
            "profile",
            "profiles",
            "member",
            "members",
            "customer",
            "customers",
            "order",
            "orders",
            "invoice",
            "invoices",
            "payment",
            "payments",
            "tenant",
            "tenants",
            "org",
            "orgs",
            "organization",
            "organizations",
            "project",
            "projects",
            "team",
            "teams",
            "document",
            "documents",
            "file",
            "files",
            "resource",
            "resources",
        }
    )
    _ID_KEYS = frozenset(
        {
            "id",
            "uid",
            "user_id",
            "userid",
            "account_id",
            "accountid",
            "member_id",
            "customer_id",
            "order_id",
            "invoice_id",
            "payment_id",
            "tenant_id",
            "org_id",
            "organization_id",
            "project_id",
            "team_id",
            "document_id",
            "doc_id",
            "file_id",
            "resource_id",
            "owner_id",
        }
    )
    _FETCH_KEYS = frozenset(
        {"url", "uri", "target", "dest", "destination", "endpoint", "feed", "proxy", "fetch", "webhook"}
    )
    _REDIRECT_KEYS = frozenset(
        {"redirect", "redirect_uri", "redirect_url", "next", "return", "return_to", "continue", "callback"}
    )
    _FILE_KEYS = frozenset(
        {"file", "filename", "path", "folder", "dir", "directory", "download", "template"}
    )

    def prioritize(self, urls: Iterable[str], *, limit: int = 200) -> list[BountyLead]:
        if not 1 <= limit <= 2_000:
            raise BountyError("lead limit must be between 1 and 2000")
        best: dict[str, BountyLead] = {}
        for raw in urls:
            lead = self.classify(raw)
            if lead is None:
                continue
            signature = f"{lead.kind}:{lead.route}"
            previous = best.get(signature)
            if previous is None or lead.score > previous.score:
                best[signature] = lead
        return sorted(best.values(), key=lambda item: (-item.score, item.route, item.url))[:limit]

    def classify(self, raw_url: str) -> BountyLead | None:
        url = raw_url.strip()
        if not url:
            return None
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        query = {key.lower(): value for key, value in parse_qsl(parsed.query, keep_blank_values=True)}
        path_words = {part.lower() for part in parsed.path.split("/") if part}
        keys = set(query)
        route = self.route_signature(url)
        reasons: list[str] = []
        score = 25
        kind = "parameterized-surface"

        has_object_word = bool(path_words & self._OBJECT_WORDS)
        has_id_key = bool(keys & self._ID_KEYS)
        has_id_path = any(self._ID_VALUE.fullmatch(part) for part in parsed.path.split("/") if part)
        if has_id_key or (has_object_word and has_id_path):
            kind = "object-access"
            score = 88
            reasons.append("object reference surface suitable for controlled authorization verification")
        elif keys & self._FETCH_KEYS:
            kind = "server-side-fetch-surface"
            score = 78
            reasons.append("URL/endpoint-like input reaches a server-side fetch candidate")
        elif keys & self._REDIRECT_KEYS:
            kind = "redirect-callback-surface"
            score = 70
            reasons.append("redirect/callback parameter is user-controlled")
        elif keys & self._FILE_KEYS:
            kind = "file-path-surface"
            score = 68
            reasons.append("file/path-like input deserves traversal and access-control review")
        elif path_words & {"admin", "internal", "debug", "actuator", "manage", "management"}:
            kind = "privileged-surface"
            score = 64
            reasons.append("privileged or diagnostic route discovered")
        elif path_words & {"graphql", "swagger", "openapi", "api-docs"}:
            kind = "api-introspection-surface"
            score = 60
            reasons.append("API schema/introspection surface can unlock deeper manual testing")
        elif path_words & {"upload", "uploads", "import", "export"}:
            kind = "file-workflow-surface"
            score = 58
            reasons.append("file workflow is usually higher value than generic parameter noise")
        elif path_words & {"oauth", "login", "signin", "reset", "token", "sso"}:
            kind = "identity-flow-surface"
            score = 55
            reasons.append("identity/session flow deserves focused logic review")
        elif query:
            reasons.append("parameterized endpoint retained after route deduplication")
        else:
            return None

        if len(query) >= 3:
            score = min(100, score + 3)
            reasons.append("multi-parameter edge")
        if parsed.scheme == "https":
            canonical = urlunsplit(("https", parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))
        else:
            canonical = urlunsplit(("http", parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))
        digest = sha256(f"{kind}|{route}".encode()).hexdigest()[:16]
        return BountyLead(
            id=f"lead-{digest}",
            kind=kind,
            url=canonical,
            route=route,
            score=score,
            confidence="high-value-lead",
            source="recon",
            reasons=tuple(reasons),
        )

    def route_signature(self, raw_url: str) -> str:
        parsed = urlsplit(raw_url)
        parts = []
        for part in parsed.path.split("/"):
            if not part:
                continue
            parts.append("{id}" if self._ID_VALUE.fullmatch(part) else part.lower())
        path = "/" + "/".join(parts)
        if path == "/":
            path = "/"
        keys = sorted({key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        query = "&".join(f"{key}={{value}}" for key in keys)
        return f"{parsed.hostname.lower() if parsed.hostname else ''}{path}" + (f"?{query}" if query else "")


CommandRunner = Callable[[list[str], Path, Mapping[str, str]], None]


class BountyRunner:
    """One-command authorized recon, triage, and controlled verification orchestration."""

    def __init__(
        self,
        *,
        command_runner: CommandRunner | None = None,
        verification_runner: VerificationRunner | None = None,
        prioritizer: EndpointPrioritizer | None = None,
    ):
        self.command_runner = command_runner or self._run_command
        self.verification_runner = verification_runner or VerificationRunner()
        self.prioritizer = prioritizer or EndpointPrioritizer()

    def run(self, manifest_path: str | Path, output_directory: str | Path) -> BountyResult:
        manifest_file = Path(manifest_path).resolve()
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise BountyError("bounty manifest must contain a JSON object")
        if manifest.get("authorized_testing") is not True:
            raise BountyError("set authorized_testing=true only for a target you are explicitly allowed to test")

        campaign = str(manifest.get("name") or manifest_file.stem)
        domain = self._normalize_domain(str(manifest.get("domain", "")))
        base = manifest_file.parent
        policy_raw = manifest.get("policy")
        if not isinstance(policy_raw, str):
            raise BountyError("bounty manifest requires a policy path")
        policy_path = self._confined_input(base, policy_raw)
        policy = ScopePolicy.load(policy_path)
        if not policy.active_testing:
            raise BountyError("policy.active_testing must be true for a live bounty campaign")
        self._assert_domain_covered(policy, domain)

        output = Path(output_directory).resolve()
        output.mkdir(parents=True, exist_ok=True)
        recon_root = output / "recon-runs"
        recon_root.mkdir(parents=True, exist_ok=True)
        script = self._resolve_script(base, manifest.get("recon_script"))
        command = [str(script), "-d", domain, "-o", str(recon_root)]
        recon_config = manifest.get("recon", {})
        if recon_config is not None and not isinstance(recon_config, Mapping):
            raise BountyError("recon config must be an object")
        if isinstance(recon_config, Mapping) and bool(recon_config.get("update_templates", False)):
            command.append("--update-templates")
        env = self._bounded_env(recon_config if isinstance(recon_config, Mapping) else {})
        self.command_runner(command, script.parent.parent, env)

        recon_run = self._latest_run(recon_root, domain)
        urls = self._read_lines(recon_run / "crawl" / "logic_idor_candidates.txt")
        urls.extend(self._read_lines(recon_run / "crawl" / "parameter_urls.txt"))
        max_leads = int(manifest.get("max_leads", 200))
        leads = self.prioritizer.prioritize(urls, limit=max_leads)
        leads.extend(self._nuclei_leads(recon_run / "scan" / "nuclei_findings.jsonl"))

        verification_summary: dict[str, Any] | None = None
        verification_raw = manifest.get("verification_manifest")
        if verification_raw is not None:
            if not isinstance(verification_raw, str):
                raise BountyError("verification_manifest must be a relative file path")
            verification_manifest = self._confined_input(base, verification_raw)
            verification_result = self.verification_runner.run(
                verification_manifest, output / "verification"
            )
            verification_summary = verification_result.to_dict()
            leads.extend(self._verification_leads(verification_summary))

        leads = self._dedupe_leads(leads)[:max_leads]
        state_path = output / "state.json"
        previous_ids = self._previous_ids(state_path)
        current_ids = {lead.id for lead in leads}
        new_ids = current_ids - previous_ids
        artifacts = {
            "board": output / "bounty-board.json",
            "report": output / "bounty-report.md",
            "state": state_path,
        }
        self._write_json(artifacts["board"], [lead.to_dict() for lead in leads])
        artifacts["report"].write_text(
            self._report(campaign, domain, recon_run, leads, new_ids, verification_summary),
            encoding="utf-8",
        )
        self._write_json(
            state_path,
            {
                "campaign": campaign,
                "domain": domain,
                "lead_ids": sorted(current_ids),
                "lead_count": len(leads),
                "new_lead_count": len(new_ids),
            },
        )
        verified_count = sum(lead.confidence == "verified" for lead in leads)
        scanner_count = sum(lead.confidence == "scanner-signal" for lead in leads)
        return BountyResult(
            campaign=campaign,
            domain=domain,
            output_directory=str(output),
            recon_run=str(recon_run),
            lead_count=len(leads),
            verified_count=verified_count,
            scanner_signal_count=scanner_count,
            new_lead_count=len(new_ids),
            artifacts={name: str(path) for name, path in artifacts.items()},
            top_leads=tuple(lead.to_dict() for lead in leads[:20]),
        )

    @staticmethod
    def _run_command(command: list[str], cwd: Path, env: Mapping[str, str]) -> None:
        subprocess.run(
            command,
            cwd=cwd,
            env={**os.environ, **dict(env)},
            check=True,
            text=True,
        )

    @staticmethod
    def _normalize_domain(raw: str) -> str:
        domain = raw.strip().lower().removeprefix("*.").rstrip(".")
        if "://" in domain or "/" in domain or ":" in domain:
            raise BountyError("domain must be a bare DNS name, not a URL")
        if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", domain):
            raise BountyError("invalid campaign domain")
        return domain

    @staticmethod
    def _confined_input(base: Path, raw: str) -> Path:
        candidate = (base / raw).resolve()
        try:
            candidate.relative_to(base)
        except ValueError as exc:
            raise BountyError("manifest inputs must stay inside the campaign directory") from exc
        if not candidate.is_file():
            raise BountyError(f"campaign input does not exist: {raw}")
        return candidate

    @staticmethod
    def _assert_domain_covered(policy: ScopePolicy, domain: str) -> None:
        covered = False
        for target in policy.targets:
            pattern = target.pattern.lower().rstrip(".")
            if pattern == domain or pattern == f"*.{domain}":
                if {"http", "https"} & set(target.schemes):
                    covered = True
                    break
        if not covered:
            raise BountyError("campaign domain is not explicitly covered by the supplied policy")

    @staticmethod
    def _resolve_script(base: Path, raw: Any) -> Path:
        if raw is not None:
            if not isinstance(raw, str):
                raise BountyError("recon_script must be a relative path")
            return BountyRunner._confined_input(base, raw)
        candidates = (
            Path(__file__).resolve().parents[2] / "scripts" / "bb-pipeline.sh",
            Path.cwd() / "scripts" / "bb-pipeline.sh",
        )
        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve()
        raise BountyError("could not locate scripts/bb-pipeline.sh; set recon_script in the manifest")

    @staticmethod
    def _bounded_env(config: Mapping[str, Any]) -> dict[str, str]:
        allowed = {
            "HTTPX_THREADS",
            "HTTPX_RPS",
            "HTTPX_TIMEOUT",
            "KATANA_DEPTH",
            "KATANA_RPS",
            "KATANA_CONCURRENCY",
            "KATANA_PARALLELISM",
            "KATANA_TIMEOUT",
            "GAU_THREADS",
            "GAU_TIMEOUT",
            "NUCLEI_RPS",
            "NUCLEI_CONCURRENCY",
            "NUCLEI_BULK",
            "NUCLEI_TIMEOUT",
            "NUCLEI_MAX_HOST_ERRORS",
            "MAX_LIVE_HOSTS",
        }
        requested = config.get("env", {})
        if requested is None:
            return {}
        if not isinstance(requested, Mapping):
            raise BountyError("recon.env must be an object")
        unknown = set(map(str, requested)) - allowed
        if unknown:
            raise BountyError(f"unsupported recon environment keys: {', '.join(sorted(unknown))}")
        result = {str(key): str(value) for key, value in requested.items()}
        for key in ("HTTPX_RPS", "KATANA_RPS", "NUCLEI_RPS"):
            if key in result and float(result[key]) > 20:
                raise BountyError(f"{key} cannot exceed 20 requests/second in bounty mode")
        return result

    @staticmethod
    def _latest_run(root: Path, domain: str) -> Path:
        campaign_root = root / domain
        runs = sorted(path for path in campaign_root.glob("*") if path.is_dir())
        if not runs:
            raise BountyError("recon pipeline completed without a run directory")
        return runs[-1]

    @staticmethod
    def _read_lines(path: Path) -> list[str]:
        if not path.is_file():
            return []
        return [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]

    @staticmethod
    def _nuclei_leads(path: Path) -> list[BountyLead]:
        if not path.is_file():
            return []
        result: list[BountyLead] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, Mapping):
                continue
            info = item.get("info", {})
            severity = str(info.get("severity", "unknown") if isinstance(info, Mapping) else "unknown").lower()
            template_id = str(item.get("template-id") or item.get("template_id") or "nuclei")
            url = str(item.get("matched-at") or item.get("matched_at") or item.get("host") or "")
            score = {"critical": 100, "high": 96, "medium": 78, "low": 55}.get(severity, 50)
            digest = sha256(f"nuclei|{template_id}|{url}".encode()).hexdigest()[:16]
            result.append(
                BountyLead(
                    id=f"nuclei-{digest}",
                    kind=f"nuclei:{template_id}",
                    url=url,
                    route=urlsplit(url).path or url,
                    score=score,
                    confidence="scanner-signal",
                    source="nuclei",
                    reasons=(f"nuclei severity: {severity}",),
                )
            )
        return result

    @staticmethod
    def _verification_leads(summary: Mapping[str, Any]) -> list[BountyLead]:
        result: list[BountyLead] = []
        top = summary.get("top_candidates", [])
        if not isinstance(top, list):
            return result
        for item in top:
            if not isinstance(item, Mapping):
                continue
            strength = str(item.get("verification_strength", "candidate"))
            confidence = "verified" if strength == "verified" else "likely"
            score = 110 if confidence == "verified" else 100
            target = str(item.get("target", ""))
            candidate_id = str(item.get("id") or sha256(target.encode()).hexdigest()[:16])
            result.append(
                BountyLead(
                    id=f"verify-{candidate_id}",
                    kind=str(item.get("kind") or "authorization"),
                    url=target,
                    route=target,
                    score=score,
                    confidence=confidence,
                    source="barq-verify",
                    reasons=("controlled identity/resource differential",),
                )
            )
        return result

    @staticmethod
    def _dedupe_leads(leads: Iterable[BountyLead]) -> list[BountyLead]:
        best: dict[str, BountyLead] = {}
        for lead in leads:
            key = lead.id
            previous = best.get(key)
            if previous is None or lead.score > previous.score:
                best[key] = lead
        return sorted(best.values(), key=lambda item: (-item.score, item.kind, item.route))

    @staticmethod
    def _previous_ids(path: Path) -> set[str]:
        if not path.is_file():
            return set()
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return set()
        ids = value.get("lead_ids", []) if isinstance(value, Mapping) else []
        return {str(item) for item in ids} if isinstance(ids, list) else set()

    @staticmethod
    def _write_json(path: Path, value: Any) -> None:
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    @staticmethod
    def _report(
        campaign: str,
        domain: str,
        recon_run: Path,
        leads: list[BountyLead],
        new_ids: set[str],
        verification: Mapping[str, Any] | None,
    ) -> str:
        verified = [lead for lead in leads if lead.confidence == "verified"]
        scanner = [lead for lead in leads if lead.confidence == "scanner-signal"]
        high_value = [lead for lead in leads if lead.confidence == "high-value-lead"]
        lines = [
            f"# BARQ Bounty Board — {campaign}",
            "",
            f"- Scope root: `{domain}`",
            f"- Recon run: `{recon_run}`",
            f"- Total prioritized leads: **{len(leads)}**",
            f"- Verified authorization findings: **{len(verified)}**",
            f"- Scanner signals: **{len(scanner)}**",
            f"- High-value manual leads: **{len(high_value)}**",
            f"- New since previous run: **{len(new_ids)}**",
            "",
            "## Priority queue",
            "",
        ]
        if not leads:
            lines.append("_No prioritized leads were produced._")
        for index, lead in enumerate(leads[:50], 1):
            marker = "NEW" if lead.id in new_ids else "seen"
            reasons = "; ".join(lead.reasons)
            lines.extend(
                [
                    f"### {index}. [{lead.score}] {lead.kind} — {lead.confidence} — {marker}",
                    f"`{lead.url}`",
                    "",
                    reasons,
                    "",
                ]
            )
        if verification is not None:
            lines.extend(
                [
                    "## Controlled verification",
                    "",
                    f"- Observations: **{verification.get('observation_count', 0)}**",
                    f"- Candidates: **{verification.get('candidate_count', 0)}**",
                    f"- Verified: **{verification.get('verified_count', 0)}**",
                    "",
                ]
            )
        lines.extend(
            [
                "## Interpretation",
                "",
                "`verified` means BARQ reproduced an authorization boundary failure using controlled accounts/resources.",
                "`scanner-signal` is a tool signal that still needs researcher confirmation.",
                "`high-value-lead` is prioritized recon, not a vulnerability claim.",
                "",
            ]
        )
        return "\n".join(lines)
