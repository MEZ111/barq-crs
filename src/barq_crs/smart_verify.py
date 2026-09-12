from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from .bounty import BountyError, BountyLead, BountyResult, BountyRunner, EndpointPrioritizer
from .scope import ScopePolicy, ScopeViolation
from .verifier import (
    ControlledResource,
    OpenApiReadTemplatePlanner,
    RequestTemplate,
    VerificationRunner,
)


class SmartVerificationError(BountyError):
    """Raised before synthesized verification can leave its controlled envelope."""


@dataclass(frozen=True, slots=True)
class SynthesizedTemplate:
    template: RequestTemplate
    score: int
    source_url: str
    reason: str

    def public_dict(self) -> dict[str, Any]:
        value = self.template.to_dict()
        value.update({"score": self.score, "reason": self.reason})
        return value


class DiscoveryTemplateSynthesizer:
    """Turn noisy discovery URLs into controlled-resource verification templates.

    It never replays arbitrary discovered identifiers. A generated request always swaps
    the discovered value for an explicitly researcher-controlled resource before live
    verification. This makes recon useful for finding authorization edges without ID
    enumeration or state-changing requests.
    """

    _DYNAMIC = re.compile(
        r"^(?:\d{2,}|[0-9a-f]{12,}|[0-9a-f]{8}(?:-[0-9a-f]{4}){2,}-[0-9a-f]{8,}|[A-Za-z0-9_-]{16,})$",
        re.IGNORECASE,
    )

    def __init__(self, prioritizer: EndpointPrioritizer | None = None):
        self.prioritizer = prioritizer or EndpointPrioritizer()

    def synthesize(
        self,
        urls: Iterable[str],
        resources: Iterable[ControlledResource],
        policy: ScopePolicy,
        *,
        parameter_bindings: Mapping[str, str] | None = None,
        max_templates: int = 200,
    ) -> list[SynthesizedTemplate]:
        if not 1 <= max_templates <= 1_000:
            raise SmartVerificationError("smart max_templates must be between 1 and 1000")
        resource_list = list(resources)
        if not resource_list:
            raise SmartVerificationError("smart verification requires controlled resources")
        bindings = {str(key).lower(): str(value) for key, value in (parameter_bindings or {}).items()}
        kinds = {resource.kind for resource in resource_list}
        unknown = sorted(set(bindings.values()) - kinds)
        if unknown:
            raise SmartVerificationError(
                "parameter bindings reference unknown resource kinds: " + ", ".join(unknown)
            )

        best: dict[tuple[str, str], SynthesizedTemplate] = {}
        for raw in urls:
            url = raw.strip()
            if not url:
                continue
            try:
                canonical = policy.authorize(url, "GET", active=True)
            except (ScopeViolation, ValueError):
                continue
            parsed = urlsplit(canonical)
            base_score = self._score(canonical)
            candidates = self._exact_candidates(parsed, resource_list, base_score)
            candidates.extend(
                self._bound_query_candidates(parsed, bindings, resource_list, base_score)
            )
            candidates.extend(self._kind_path_candidates(parsed, resource_list, base_score))
            for candidate in candidates:
                key = (candidate.template.url, candidate.template.resource_kind or "")
                previous = best.get(key)
                if previous is None or candidate.score > previous.score:
                    best[key] = candidate

        return sorted(
            best.values(),
            key=lambda item: (-item.score, item.template.resource_kind or "", item.template.url),
        )[:max_templates]

    def _exact_candidates(
        self,
        parsed: Any,
        resources: list[ControlledResource],
        score: int,
    ) -> list[SynthesizedTemplate]:
        result: list[SynthesizedTemplate] = []
        path_parts = parsed.path.split("/")
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        for resource in resources:
            for index, part in enumerate(path_parts):
                if part and unquote(part) == resource.value:
                    replaced = list(path_parts)
                    replaced[index] = "{resource}"
                    url = urlunsplit(
                        (parsed.scheme, parsed.netloc, "/".join(replaced), parsed.query, "")
                    )
                    result.append(
                        self._candidate(
                            url,
                            resource.kind,
                            score + 12,
                            "exact controlled resource observed in path",
                        )
                    )
            for index, (key, value) in enumerate(query_pairs):
                if value != resource.value:
                    continue
                replaced_pairs = list(query_pairs)
                replaced_pairs[index] = (key, "{resource}")
                url = self._with_query(parsed, replaced_pairs)
                result.append(
                    self._candidate(
                        url,
                        resource.kind,
                        score + 10,
                        f"exact controlled resource observed in query parameter {key}",
                    )
                )
        return result

    def _bound_query_candidates(
        self,
        parsed: Any,
        bindings: Mapping[str, str],
        resources: list[ControlledResource],
        score: int,
    ) -> list[SynthesizedTemplate]:
        if not bindings:
            return []
        available = {resource.kind for resource in resources}
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        result: list[SynthesizedTemplate] = []
        for index, (key, _value) in enumerate(pairs):
            kind = bindings.get(key.lower())
            if not kind or kind not in available:
                continue
            replaced = list(pairs)
            replaced[index] = (key, "{resource}")
            result.append(
                self._candidate(
                    self._with_query(parsed, replaced),
                    kind,
                    score + 8,
                    f"explicit query binding {key}->{kind}",
                )
            )
        return result

    def _kind_path_candidates(
        self,
        parsed: Any,
        resources: list[ControlledResource],
        score: int,
    ) -> list[SynthesizedTemplate]:
        parts = parsed.path.split("/")
        kinds = sorted({resource.kind.lower() for resource in resources})
        result: list[SynthesizedTemplate] = []
        for index in range(1, len(parts)):
            current = unquote(parts[index])
            previous = unquote(parts[index - 1]).lower()
            if not current or not self._DYNAMIC.fullmatch(current):
                continue
            for kind in kinds:
                aliases = {kind, f"{kind}s", f"{kind}es"}
                if previous not in aliases:
                    continue
                replaced = list(parts)
                replaced[index] = "{resource}"
                result.append(
                    self._candidate(
                        urlunsplit(
                            (parsed.scheme, parsed.netloc, "/".join(replaced), parsed.query, "")
                        ),
                        kind,
                        score + 6,
                        f"resource-kind route edge {previous}/<id>",
                    )
                )
        return result

    @staticmethod
    def _with_query(parsed: Any, pairs: list[tuple[str, str]]) -> str:
        encoded = urlencode(pairs, doseq=True)
        encoded = encoded.replace("%7Bresource%7D", "{resource}")
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, encoded, ""))

    @staticmethod
    def _candidate(url: str, kind: str, score: int, reason: str) -> SynthesizedTemplate:
        route = urlsplit(url).path or "/"
        name = "smart_" + re.sub(r"[^A-Za-z0-9]+", "_", f"{kind}_{route}").strip("_")[:90]
        return SynthesizedTemplate(
            template=RequestTemplate(
                name=name,
                url=url,
                method="GET",
                route=route,
                resource_kind=kind,
                tags=("smart-discovery", "controlled-resource-swap"),
            ),
            score=min(100, score),
            source_url=url,
            reason=reason,
        )

    def _score(self, url: str) -> int:
        lead = self.prioritizer.classify(url)
        return lead.score if lead is not None else 45


class SmartBountyRunner:
    """BARQ bounty runner with budget-aware discovery-to-verification synthesis."""

    def __init__(
        self,
        *,
        base_runner: BountyRunner | None = None,
        verification_runner: VerificationRunner | None = None,
        synthesizer: DiscoveryTemplateSynthesizer | None = None,
    ):
        self.base_runner = base_runner or BountyRunner()
        self.verification_runner = verification_runner or VerificationRunner()
        self.synthesizer = synthesizer or DiscoveryTemplateSynthesizer()

    def run(self, manifest_path: str | Path, output_directory: str | Path) -> BountyResult:
        manifest_file = Path(manifest_path).resolve()
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise SmartVerificationError("bounty manifest must contain a JSON object")
        output = Path(output_directory).resolve()
        previous_ids = BountyRunner._previous_ids(output / "state.json")
        base_result = self.base_runner.run(manifest_file, output)

        config = manifest.get("smart_verification")
        if config is None:
            return base_result
        if not isinstance(config, Mapping):
            raise SmartVerificationError("smart_verification must be an object")
        if config.get("enabled", True) is not True:
            return base_result

        verify_raw = config.get("manifest")
        if not isinstance(verify_raw, str):
            raise SmartVerificationError("smart_verification.manifest must be a relative file path")
        verify_file = BountyRunner._confined_input(manifest_file.parent, verify_raw)
        verify_doc = json.loads(verify_file.read_text(encoding="utf-8"))
        if not isinstance(verify_doc, dict):
            raise SmartVerificationError("smart verification manifest must contain a JSON object")
        verify_base = verify_file.parent

        policy_raw = verify_doc.get("policy")
        profiles_raw = verify_doc.get("profiles")
        if not isinstance(policy_raw, str) or not isinstance(profiles_raw, str):
            raise SmartVerificationError("smart verification manifest requires policy and profiles")
        policy = ScopePolicy.load(VerificationRunner._input(verify_base, policy_raw))
        resource_values = VerificationRunner._load_list(
            verify_base, verify_doc.get("resources", []), "resources"
        )
        resources = [
            ControlledResource.from_dict(item)
            for item in resource_values
            if isinstance(item, Mapping)
        ]
        profile_values = VerificationRunner._load_list(verify_base, profiles_raw, "profiles")
        profile_count = self._profile_count(profile_values, bool(verify_doc.get("include_anonymous", True)))
        if profile_count < 1:
            raise SmartVerificationError("smart verification requires at least one profile")

        discovery_urls = self._discovery_urls(Path(base_result.recon_run))
        bindings_raw = config.get("parameter_bindings", {})
        if not isinstance(bindings_raw, Mapping):
            raise SmartVerificationError("smart_verification.parameter_bindings must be an object")
        max_templates = int(config.get("max_templates", 120))
        synthesized = self.synthesizer.synthesize(
            discovery_urls,
            resources,
            policy,
            parameter_bindings={str(key): str(value) for key, value in bindings_raw.items()},
            max_templates=max_templates,
        )

        existing_raw = VerificationRunner._load_list(
            verify_base, verify_doc.get("templates", []), "templates"
        )
        existing = [
            RequestTemplate.from_dict(item)
            for item in existing_raw
            if isinstance(item, Mapping)
        ]
        openapi_templates = self._openapi_templates(verify_base, verify_doc)
        limits = verify_doc.get("limits", {})
        if not isinstance(limits, Mapping):
            raise SmartVerificationError("verification limits must be an object")
        max_requests = int(limits.get("max_requests", 100))
        selected, estimated = self._fit_budget(
            existing,
            openapi_templates,
            synthesized,
            resources,
            profile_count,
            max_requests,
        )
        if not selected and not existing and not openapi_templates:
            raise SmartVerificationError(
                "no safe smart verification templates fit the configured request budget"
            )

        derived = dict(verify_doc)
        derived["name"] = str(verify_doc.get("name") or manifest.get("name") or "smart-verification")
        derived["templates"] = [template.to_dict() for template in existing] + [
            item.template.to_dict() for item in selected
        ]
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=".json",
                prefix=".barq-smart-",
                dir=verify_base,
                delete=False,
            ) as handle:
                json.dump(derived, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
                temp_path = Path(handle.name)
            verification = self.verification_runner.run(temp_path, output / "smart-verification")
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

        verification_summary = verification.to_dict()
        smart_plan = output / "smart-verification-plan.json"
        smart_plan.write_text(
            json.dumps(
                {
                    "discovery_url_count": len(discovery_urls),
                    "candidate_template_count": len(synthesized),
                    "selected_template_count": len(selected),
                    "existing_template_count": len(existing),
                    "openapi_template_count": len(openapi_templates),
                    "profile_count": profile_count,
                    "estimated_request_count": estimated,
                    "max_requests": max_requests,
                    "selected": [item.public_dict() for item in selected],
                    "dropped_for_budget": max(0, len(synthesized) - len(selected)),
                    "read_only": True,
                    "controlled_resources_only": True,
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )

        base_leads = self._load_board(output / "bounty-board.json")
        base_leads.extend(BountyRunner._verification_leads(verification_summary))
        max_leads = int(manifest.get("max_leads", 200))
        merged = BountyRunner._dedupe_leads(base_leads)[:max_leads]
        current_ids = {lead.id for lead in merged}
        new_ids = current_ids - previous_ids
        board_path = output / "bounty-board.json"
        report_path = output / "bounty-report.md"
        state_path = output / "state.json"
        BountyRunner._write_json(board_path, [lead.to_dict() for lead in merged])
        report_path.write_text(
            BountyRunner._report(
                base_result.campaign,
                base_result.domain,
                Path(base_result.recon_run),
                merged,
                new_ids,
                verification_summary,
            ),
            encoding="utf-8",
        )
        BountyRunner._write_json(
            state_path,
            {
                "campaign": base_result.campaign,
                "domain": base_result.domain,
                "lead_ids": sorted(current_ids),
                "lead_count": len(merged),
                "new_lead_count": len(new_ids),
                "smart_verification": True,
            },
        )
        artifacts = dict(base_result.artifacts)
        artifacts.update(
            {
                "smart_plan": str(smart_plan),
                "smart_verification_summary": verification_summary["artifacts"]["summary"],
            }
        )
        return BountyResult(
            campaign=base_result.campaign,
            domain=base_result.domain,
            output_directory=base_result.output_directory,
            recon_run=base_result.recon_run,
            lead_count=len(merged),
            verified_count=sum(lead.confidence == "verified" for lead in merged),
            scanner_signal_count=sum(lead.confidence == "scanner-signal" for lead in merged),
            new_lead_count=len(new_ids),
            artifacts=artifacts,
            top_leads=tuple(lead.to_dict() for lead in merged[:20]),
        )

    @staticmethod
    def _discovery_urls(recon_run: Path) -> list[str]:
        values: list[str] = []
        for relative in (
            "crawl/logic_idor_candidates.txt",
            "crawl/parameter_urls.txt",
            "crawl/all_scoped_urls.txt",
        ):
            values.extend(BountyRunner._read_lines(recon_run / relative))
        return list(dict.fromkeys(values))

    @staticmethod
    def _profile_count(values: list[Any], include_anonymous: bool) -> int:
        profiles = [item for item in values if isinstance(item, Mapping)]
        explicit_anonymous = any(
            str(item.get("principal", "")).lower() == "anonymous"
            or str(item.get("role", "")).lower() == "anonymous"
            for item in profiles
        )
        return len(profiles) + (1 if include_anonymous and not explicit_anonymous else 0)

    @staticmethod
    def _template_expansion(template: RequestTemplate, resources: list[ControlledResource]) -> int:
        if template.resource_kind is None:
            return 1
        return sum(resource.kind == template.resource_kind for resource in resources)

    @classmethod
    def _fit_budget(
        cls,
        existing: list[RequestTemplate],
        openapi: list[RequestTemplate],
        synthesized: list[SynthesizedTemplate],
        resources: list[ControlledResource],
        profile_count: int,
        max_requests: int,
    ) -> tuple[list[SynthesizedTemplate], int]:
        if max_requests < 1:
            raise SmartVerificationError("verification max_requests must be positive")
        base_units = sum(cls._template_expansion(item, resources) for item in (*existing, *openapi))
        used = base_units * profile_count
        if used > max_requests:
            raise SmartVerificationError(
                f"existing verification plan already exceeds request budget: {used}>{max_requests}"
            )
        selected: list[SynthesizedTemplate] = []
        for item in synthesized:
            units = cls._template_expansion(item.template, resources)
            cost = units * profile_count
            if units < 1 or used + cost > max_requests:
                continue
            selected.append(item)
            used += cost
        return selected, used

    @staticmethod
    def _openapi_templates(base: Path, document: Mapping[str, Any]) -> list[RequestTemplate]:
        config = document.get("openapi")
        if config is None:
            return []
        if not isinstance(config, Mapping):
            raise SmartVerificationError("openapi verification config must be an object")
        spec_raw = config.get("spec")
        base_url = config.get("base_url")
        if not isinstance(spec_raw, str) or not isinstance(base_url, str):
            raise SmartVerificationError("openapi config requires spec and base_url")
        spec = VerificationRunner._load_object(base, spec_raw, "openapi.spec")
        bindings = config.get("resource_parameters", {})
        if not isinstance(bindings, Mapping):
            raise SmartVerificationError("openapi.resource_parameters must be an object")
        plan = OpenApiReadTemplatePlanner().plan(
            spec,
            base_url=base_url,
            resource_parameters={str(key): str(value) for key, value in bindings.items()},
            include_public=bool(config.get("include_public", False)),
            max_templates=int(config.get("max_templates", 250)),
        )
        return list(plan.templates)

    @staticmethod
    def _load_board(path: Path) -> list[BountyLead]:
        if not path.is_file():
            return []
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, list):
            return []
        result: list[BountyLead] = []
        for item in value:
            if not isinstance(item, Mapping):
                continue
            result.append(
                BountyLead(
                    id=str(item.get("id", "")),
                    kind=str(item.get("kind", "")),
                    url=str(item.get("url", "")),
                    route=str(item.get("route", "")),
                    score=int(item.get("score", 0)),
                    confidence=str(item.get("confidence", "")),
                    source=str(item.get("source", "")),
                    reasons=tuple(str(reason) for reason in item.get("reasons", [])),
                )
            )
        return result
