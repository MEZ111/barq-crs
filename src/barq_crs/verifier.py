from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import quote, urlsplit

from .authz import AuthorizationDifferentialEngine, response_summary
from .collector import CollectorLimits, EvidenceCollector, RequestSpec, SessionProfile
from .fusion import SignalFusion
from .ledger import EvidenceLedger
from .models import Candidate, Observation
from .report import markdown_report
from .sarif import sarif_report
from .scope import SAFE_METHODS, ScopePolicy


_RESOURCE_PLACEHOLDER = "{resource}"
_PATH_PARAMETER = re.compile(r"\{([^{}]+)\}")
_STRENGTH = {"candidate": 0, "likely": 1, "verified": 2}


class VerificationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ControlledResource:
    """One harmless resource explicitly controlled by a research identity."""

    key: str
    kind: str
    value: str
    owner: str
    tenant: str | None = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ControlledResource":
        resource = cls(
            key=str(value.get("key", "")).strip(),
            kind=str(value.get("kind", "")).strip(),
            value=str(value.get("value", "")).strip(),
            owner=str(value.get("owner", "")).strip(),
            tenant=(str(value["tenant"]).strip() if value.get("tenant") is not None else None),
        )
        resource.validate()
        return resource

    def validate(self) -> None:
        if not self.key or len(self.key) > 128:
            raise VerificationError("resource key must be between 1 and 128 characters")
        if not re.fullmatch(r"[A-Za-z0-9_.:@-]+", self.key):
            raise VerificationError(f"resource key contains unsafe characters: {self.key}")
        if not self.kind or len(self.kind) > 80:
            raise VerificationError(f"resource {self.key} needs a short kind")
        if not self.value or len(self.value) > 512:
            raise VerificationError(f"resource {self.key} needs a bounded non-empty value")
        if not self.owner or self.owner.lower() == "anonymous":
            raise VerificationError(f"resource {self.key} needs a controlled non-anonymous owner")
        if "\r" in self.value or "\n" in self.value:
            raise VerificationError(f"resource {self.key} value contains a line break")

    def public_dict(self) -> dict[str, Any]:
        """Describe the fixture without persisting the raw identifier value."""
        return {
            "key": self.key,
            "kind": self.kind,
            "owner": self.owner,
            "tenant": self.tenant,
        }


@dataclass(frozen=True, slots=True)
class RequestTemplate:
    name: str
    url: str
    method: str = "GET"
    route: str | None = None
    resource_kind: str | None = None
    tags: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RequestTemplate":
        template = cls(
            name=str(value.get("name", "")).strip(),
            url=str(value.get("url", "")).strip(),
            method=str(value.get("method", "GET")).upper(),
            route=(str(value["route"]).strip() if value.get("route") is not None else None),
            resource_kind=(
                str(value["resource_kind"]).strip()
                if value.get("resource_kind") is not None
                else None
            ),
            tags=tuple(str(tag) for tag in value.get("tags", [])),
        )
        template.validate()
        return template

    def validate(self) -> None:
        if not self.name or len(self.name) > 120:
            raise VerificationError("request template needs a bounded name")
        if self.method not in SAFE_METHODS:
            raise VerificationError(
                f"template {self.name} is not read-only: {self.method}"
            )
        parsed = urlsplit(self.url.replace(_RESOURCE_PLACEHOLDER, "barq-fixture"))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise VerificationError(f"template {self.name} needs an absolute HTTP(S) URL")
        placeholders = self.url.count(_RESOURCE_PLACEHOLDER)
        if self.resource_kind:
            if placeholders != 1:
                raise VerificationError(
                    f"template {self.name} must contain exactly one {_RESOURCE_PLACEHOLDER} placeholder"
                )
        elif placeholders:
            raise VerificationError(
                f"template {self.name} uses {_RESOURCE_PLACEHOLDER} without resource_kind"
            )

    def render(self, resource: ControlledResource | None = None) -> RequestSpec:
        if self.resource_kind:
            if resource is None or resource.kind != self.resource_kind:
                raise VerificationError(
                    f"template {self.name} requires resource kind {self.resource_kind}"
                )
            encoded = quote(resource.value, safe="")
            rendered_url = self.url.replace(_RESOURCE_PLACEHOLDER, encoded)
            route = self.route or urlsplit(self.url).path
            return RequestSpec(
                rendered_url,
                method=self.method,
                route=route,
                resource_id=resource.key,
                resource_tenant=resource.tenant,
                tags=(*self.tags, f"template:{self.name}", "controlled-resource-swap"),
            )
        return RequestSpec(
            self.url,
            method=self.method,
            route=self.route or urlsplit(self.url).path,
            tags=(*self.tags, f"template:{self.name}", "controlled-identity-swap"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "method": self.method,
            "route": self.route,
            "resource_kind": self.resource_kind,
            "tags": list(self.tags),
        }


@dataclass(frozen=True, slots=True)
class OpenApiPlan:
    templates: tuple[RequestTemplate, ...]
    skipped: tuple[str, ...]


class OpenApiReadTemplatePlanner:
    """Turn explicitly bound read-only OpenAPI operations into live templates.

    The planner never guesses identifiers and never enumerates values. Path parameters
    are live-testable only when the manifest maps the parameter to a controlled
    resource kind.
    """

    def plan(
        self,
        document: Mapping[str, Any],
        *,
        base_url: str,
        resource_parameters: Mapping[str, str] | None = None,
        include_public: bool = False,
        max_templates: int = 250,
    ) -> OpenApiPlan:
        if not 1 <= max_templates <= 1_000:
            raise VerificationError("max_templates must be between 1 and 1000")
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise VerificationError("OpenAPI verification requires an explicit absolute base_url")
        if parsed.query or parsed.fragment:
            raise VerificationError("OpenAPI verification base_url cannot contain query or fragment")
        bindings = {str(key): str(value) for key, value in (resource_parameters or {}).items()}
        paths = document.get("paths", {})
        if not isinstance(paths, Mapping):
            raise VerificationError("OpenAPI paths must be an object")
        global_security = document.get("security")
        templates: list[RequestTemplate] = []
        skipped: list[str] = []
        for path, path_item in sorted(paths.items(), key=lambda item: str(item[0])):
            if not isinstance(path, str) or not isinstance(path_item, Mapping):
                continue
            for method in ("get", "head", "options"):
                operation = path_item.get(method)
                if not isinstance(operation, Mapping):
                    continue
                security = operation.get("security", global_security)
                authenticated = not self._anonymous(security)
                operation_id = str(operation.get("operationId") or f"{method}_{self._slug(path)}")
                target = f"{method.upper()} {path}"
                if not authenticated and not include_public:
                    skipped.append(f"{target}: public by contract")
                    continue
                parameters = _PATH_PARAMETER.findall(path)
                if not parameters:
                    template_url = self._join(base_url, path)
                    templates.append(
                        RequestTemplate(
                            name=operation_id,
                            url=template_url,
                            method=method.upper(),
                            route=path,
                            tags=("openapi", "secured" if authenticated else "public"),
                        )
                    )
                elif len(parameters) == 1 and parameters[0] in bindings:
                    parameter = parameters[0]
                    kind = bindings[parameter]
                    if not kind:
                        skipped.append(f"{target}: empty resource binding for {parameter}")
                        continue
                    template_path = path.replace("{" + parameter + "}", _RESOURCE_PLACEHOLDER)
                    templates.append(
                        RequestTemplate(
                            name=operation_id,
                            url=self._join(base_url, template_path),
                            method=method.upper(),
                            route=path,
                            resource_kind=kind,
                            tags=("openapi", "secured" if authenticated else "public"),
                        )
                    )
                else:
                    unresolved = ", ".join(parameters) if parameters else "none"
                    skipped.append(f"{target}: unresolved path parameters ({unresolved})")
                if len(templates) >= max_templates:
                    skipped.append("template budget reached")
                    return OpenApiPlan(tuple(self._dedupe(templates)), tuple(skipped))
        return OpenApiPlan(tuple(self._dedupe(templates)), tuple(skipped))

    @staticmethod
    def _anonymous(security: Any) -> bool:
        return security is None or security == [] or (
            isinstance(security, list) and any(item == {} for item in security)
        )

    @staticmethod
    def _join(base_url: str, path: str) -> str:
        return base_url.rstrip("/") + "/" + path.lstrip("/")

    @staticmethod
    def _slug(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()

    @staticmethod
    def _dedupe(templates: Iterable[RequestTemplate]) -> list[RequestTemplate]:
        result: list[RequestTemplate] = []
        seen: set[tuple[str, str, str | None]] = set()
        for template in templates:
            key = (template.method, template.url, template.resource_kind)
            if key not in seen:
                result.append(template)
                seen.add(key)
        return result


@dataclass(frozen=True, slots=True)
class VerificationRun:
    observations: tuple[Observation, ...]
    candidates: tuple[Candidate, ...]
    requests: tuple[RequestSpec, ...]
    profiles: tuple[SessionProfile, ...]

    @property
    def verified_count(self) -> int:
        return sum(_candidate_strength(item) == "verified" for item in self.candidates)


class ActiveAuthorizationVerifier:
    """Execute a bounded controlled-identity/resource matrix and analyze it."""

    def __init__(
        self,
        *,
        engine: AuthorizationDifferentialEngine | None = None,
        collector_factory: Callable[[ScopePolicy, CollectorLimits], EvidenceCollector] | None = None,
    ):
        self.engine = engine or AuthorizationDifferentialEngine()
        self.collector_factory = collector_factory or (
            lambda policy, limits: EvidenceCollector(policy, limits)
        )

    def run(
        self,
        policy: ScopePolicy,
        profiles: Iterable[SessionProfile],
        resources: Iterable[ControlledResource],
        templates: Iterable[RequestTemplate],
        *,
        include_anonymous: bool = True,
        limits: CollectorLimits | None = None,
    ) -> VerificationRun:
        resource_list = list(resources)
        template_list = list(templates)
        profile_list = list(profiles)
        self._validate_inputs(profile_list, resource_list, template_list)
        enriched_profiles = self._owned_profiles(profile_list, resource_list)
        if include_anonymous and not any(
            profile.role.lower() == "anonymous" or profile.principal.lower() == "anonymous"
            for profile in enriched_profiles
        ):
            enriched_profiles.append(
                SessionProfile(
                    principal="anonymous",
                    role="anonymous",
                    headers={},
                    tenant=None,
                    owned_resource_ids=frozenset(),
                )
            )
        requests = self._requests(template_list, resource_list)
        collector_limits = limits or CollectorLimits()
        total = len(requests) * len(enriched_profiles)
        if total > collector_limits.max_requests:
            raise VerificationError(
                f"verification matrix exceeds budget before network access: {total}>{collector_limits.max_requests}"
            )
        observations = self.collector_factory(policy, collector_limits).collect_matrix(
            requests, enriched_profiles
        )
        findings = self.engine.analyze(observations)
        return VerificationRun(
            observations=tuple(observations),
            candidates=tuple(findings),
            requests=tuple(requests),
            profiles=tuple(enriched_profiles),
        )

    @staticmethod
    def _validate_inputs(
        profiles: list[SessionProfile],
        resources: list[ControlledResource],
        templates: list[RequestTemplate],
    ) -> None:
        if not profiles:
            raise VerificationError("verification requires at least one controlled session profile")
        if not templates:
            raise VerificationError("verification requires at least one read-only request template")
        principals = [profile.principal for profile in profiles]
        if len(principals) != len(set(principals)):
            raise VerificationError("session profile principals must be unique")
        controlled = set(principals)
        keys = [resource.key for resource in resources]
        if len(keys) != len(set(keys)):
            raise VerificationError("controlled resource keys must be unique")
        kind_values = [(resource.kind, resource.value) for resource in resources]
        if len(kind_values) != len(set(kind_values)):
            raise VerificationError("controlled resource values must be unique within each kind")
        for resource in resources:
            resource.validate()
            if resource.owner not in controlled:
                raise VerificationError(
                    f"resource {resource.key} owner is not a configured principal: {resource.owner}"
                )
        for template in templates:
            template.validate()
            if template.resource_kind and not any(
                resource.kind == template.resource_kind for resource in resources
            ):
                raise VerificationError(
                    f"template {template.name} has no controlled resources of kind {template.resource_kind}"
                )

    @staticmethod
    def _owned_profiles(
        profiles: list[SessionProfile], resources: list[ControlledResource]
    ) -> list[SessionProfile]:
        ownership: dict[str, set[str]] = {profile.principal: set() for profile in profiles}
        for resource in resources:
            ownership[resource.owner].add(resource.key)
        return [
            replace(profile, owned_resource_ids=frozenset(ownership[profile.principal]))
            for profile in profiles
        ]

    @staticmethod
    def _requests(
        templates: list[RequestTemplate], resources: list[ControlledResource]
    ) -> list[RequestSpec]:
        result: list[RequestSpec] = []
        for template in templates:
            if template.resource_kind:
                for resource in resources:
                    if resource.kind == template.resource_kind:
                        result.append(template.render(resource))
            else:
                result.append(template.render())
        return result


@dataclass(frozen=True, slots=True)
class VerificationResult:
    campaign: str
    output_directory: str
    observation_count: int
    candidate_count: int
    verified_count: int
    high_or_critical_count: int
    request_template_count: int
    controlled_resource_count: int
    artifacts: dict[str, str]
    top_candidates: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["top_candidates"] = list(self.top_candidates)
        return value


class VerificationRunner:
    """Load a secret-free manifest, run live read-only verification, and persist sanitized proof."""

    def __init__(
        self,
        *,
        verifier: ActiveAuthorizationVerifier | None = None,
        openapi_planner: OpenApiReadTemplatePlanner | None = None,
    ):
        self.verifier = verifier or ActiveAuthorizationVerifier()
        self.openapi_planner = openapi_planner or OpenApiReadTemplatePlanner()

    def run(self, manifest_path: str | Path, output_directory: str | Path) -> VerificationResult:
        manifest_file = Path(manifest_path).resolve()
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise VerificationError("verification manifest must contain a JSON object")
        base = manifest_file.parent
        campaign = str(manifest.get("name") or manifest_file.stem)
        policy_raw = manifest.get("policy")
        profiles_raw = manifest.get("profiles")
        if not isinstance(policy_raw, str) or not isinstance(profiles_raw, str):
            raise VerificationError("verification manifest requires policy and profiles file paths")
        policy = ScopePolicy.load(self._input(base, policy_raw))
        profiles = [
            SessionProfile.from_env_dict(item)
            for item in self._load_list(base, profiles_raw, "profiles")
            if isinstance(item, Mapping)
        ]
        resources = [
            ControlledResource.from_dict(item)
            for item in self._load_list(base, manifest.get("resources", []), "resources")
            if isinstance(item, Mapping)
        ]
        templates = [
            RequestTemplate.from_dict(item)
            for item in self._load_list(base, manifest.get("templates", []), "templates")
            if isinstance(item, Mapping)
        ]
        skipped: list[str] = []
        openapi_config = manifest.get("openapi")
        if openapi_config is not None:
            if not isinstance(openapi_config, Mapping):
                raise VerificationError("openapi verification config must be an object")
            spec_raw = openapi_config.get("spec")
            base_url = openapi_config.get("base_url")
            if not isinstance(spec_raw, str) or not isinstance(base_url, str):
                raise VerificationError("openapi config requires spec and base_url")
            document = self._load_object(base, spec_raw, "openapi.spec")
            bindings = openapi_config.get("resource_parameters", {})
            if not isinstance(bindings, Mapping):
                raise VerificationError("openapi.resource_parameters must be an object")
            plan = self.openapi_planner.plan(
                document,
                base_url=base_url,
                resource_parameters={str(key): str(value) for key, value in bindings.items()},
                include_public=bool(openapi_config.get("include_public", False)),
                max_templates=int(openapi_config.get("max_templates", 250)),
            )
            templates.extend(plan.templates)
            skipped.extend(plan.skipped)
        templates = OpenApiReadTemplatePlanner._dedupe(templates)
        limits_raw = manifest.get("limits", {})
        if not isinstance(limits_raw, Mapping):
            raise VerificationError("verification limits must be an object")
        limits = CollectorLimits(
            max_requests=int(limits_raw.get("max_requests", 100)),
            max_body_bytes=int(limits_raw.get("max_body_bytes", 1_000_000)),
            timeout_seconds=float(limits_raw.get("timeout_seconds", 10.0)),
        )
        run = self.verifier.run(
            policy,
            profiles,
            resources,
            templates,
            include_anonymous=bool(manifest.get("include_anonymous", True)),
            limits=limits,
        )
        ranked = SignalFusion().rank(run.candidates)
        output = Path(output_directory).resolve()
        output.mkdir(parents=True, exist_ok=True)
        generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
        artifacts = {
            "report": output / "report.md",
            "findings": output / "findings.json",
            "evidence": output / "evidence.json",
            "plan": output / "verification-plan.json",
            "sarif": output / "results.sarif",
            "ledger": output / "evidence-ledger.jsonl",
            "summary": output / "summary.json",
        }
        artifacts["report"].write_text(markdown_report(ranked, campaign), encoding="utf-8")
        self._write_json(artifacts["findings"], [item.candidate.to_dict() for item in ranked])
        self._write_json(
            artifacts["evidence"],
            [self._sanitized_observation(observation) for observation in run.observations],
        )
        self._write_json(
            artifacts["plan"],
            {
                "campaign": campaign,
                "policy": policy.name,
                "policy_digest": policy.digest,
                "profiles": [profile.principal for profile in run.profiles],
                "resources": [resource.public_dict() for resource in resources],
                "templates": [template.to_dict() for template in templates],
                "skipped_openapi_operations": skipped,
                "request_count": len(run.requests) * len(run.profiles),
                "read_only": True,
            },
        )
        self._write_json(artifacts["sarif"], sarif_report(item.candidate for item in ranked))
        artifacts["ledger"].write_text("", encoding="utf-8")
        ledger = EvidenceLedger(artifacts["ledger"])
        ledger.append(
            "verification-start",
            generated,
            {
                "campaign": campaign,
                "policy_digest": policy.digest,
                "observation_count": len(run.observations),
                "template_count": len(templates),
                "resource_count": len(resources),
            },
        )
        for item in ranked:
            candidate = item.candidate
            ledger.append(
                "verified-candidate",
                generated,
                {
                    "id": candidate.id,
                    "kind": candidate.kind,
                    "target": candidate.target,
                    "severity": candidate.severity,
                    "verification_strength": _candidate_strength(candidate),
                    "priority_score": item.priority_score,
                    "evidence_fingerprints": [evidence.fingerprint for evidence in candidate.evidence],
                },
            )
        valid, ledger_message = ledger.verify()
        if not valid:
            raise RuntimeError(ledger_message)
        result = VerificationResult(
            campaign=campaign,
            output_directory=str(output),
            observation_count=len(run.observations),
            candidate_count=len(ranked),
            verified_count=sum(
                _candidate_strength(item.candidate) == "verified" for item in ranked
            ),
            high_or_critical_count=sum(
                item.candidate.severity.lower() in {"high", "critical"} for item in ranked
            ),
            request_template_count=len(templates),
            controlled_resource_count=len(resources),
            artifacts={name: str(path) for name, path in artifacts.items()},
            top_candidates=tuple(
                {
                    "id": item.candidate.id,
                    "title": item.candidate.title,
                    "target": item.candidate.target,
                    "severity": item.candidate.severity,
                    "verification_strength": _candidate_strength(item.candidate),
                    "priority_score": item.priority_score,
                }
                for item in ranked[:10]
            ),
        )
        self._write_json(
            artifacts["summary"],
            {**result.to_dict(), "generated": generated, "ledger": ledger_message},
        )
        return result

    @staticmethod
    def _sanitized_observation(observation: Observation) -> dict[str, Any]:
        return {
            "timestamp": observation.timestamp,
            "method": observation.method,
            "route": observation.route,
            "principal": observation.principal,
            "role": observation.role,
            "status": observation.status,
            "resource_id": observation.resource_id,
            "owns_resource": observation.owns_resource,
            "principal_tenant": observation.principal_tenant,
            "resource_tenant": observation.resource_tenant,
            "latency_ms": observation.latency_ms,
            "tags": list(observation.tags),
            "response": response_summary(observation.body),
        }

    @staticmethod
    def _input(base: Path, raw: str) -> Path:
        candidate = Path(raw)
        resolved = candidate.resolve() if candidate.is_absolute() else (base / candidate).resolve()
        try:
            resolved.relative_to(base)
        except ValueError as exc:
            raise VerificationError(f"verification input escapes its directory: {raw}") from exc
        if not resolved.exists():
            raise FileNotFoundError(resolved)
        return resolved

    @staticmethod
    def _load_list(base: Path, raw: Any, label: str) -> list[Any]:
        if isinstance(raw, list):
            return raw
        if isinstance(raw, str):
            value = json.loads(VerificationRunner._input(base, raw).read_text(encoding="utf-8"))
            if isinstance(value, list):
                return value
        raise VerificationError(f"{label} must be a JSON array or path to one")

    @staticmethod
    def _load_object(base: Path, raw: str, label: str) -> dict[str, Any]:
        value = json.loads(VerificationRunner._input(base, raw).read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise VerificationError(f"{label} must contain a JSON object")
        return value

    @staticmethod
    def _write_json(path: Path, value: Any) -> None:
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _candidate_strength(candidate: Candidate) -> str:
    best = "candidate"
    for evidence in candidate.evidence:
        value = str(evidence.metadata.get("verification_strength", "candidate"))
        if _STRENGTH.get(value, 0) > _STRENGTH[best]:
            best = value
    return best
