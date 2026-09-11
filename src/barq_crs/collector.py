from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .models import Observation
from .scope import SAFE_METHODS, ScopePolicy, ScopeViolation


class CollectionError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


@dataclass(frozen=True, slots=True)
class RequestSpec:
    url: str
    method: str = "GET"
    route: str | None = None
    resource_id: str | None = None
    owns_resource: bool | None = None
    resource_tenant: str | None = None
    tags: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RequestSpec":
        return cls(
            url=str(value["url"]),
            method=str(value.get("method", "GET")).upper(),
            route=str(value["route"]) if value.get("route") is not None else None,
            resource_id=(
                str(value["resource_id"])
                if value.get("resource_id") is not None
                else None
            ),
            owns_resource=value.get("owns_resource"),
            resource_tenant=(
                str(value["resource_tenant"])
                if value.get("resource_tenant") is not None
                else None
            ),
            tags=tuple(str(tag) for tag in value.get("tags", [])),
        )


@dataclass(frozen=True, slots=True)
class SessionProfile:
    principal: str
    role: str
    headers: Mapping[str, str]
    tenant: str | None = None
    owned_resource_ids: frozenset[str] | None = None

    @classmethod
    def from_env_dict(
        cls,
        value: Mapping[str, Any],
        environment: Mapping[str, str] | None = None,
    ) -> "SessionProfile":
        environment = environment if environment is not None else os.environ
        headers: dict[str, str] = {}
        for header, variable in value.get("header_env", {}).items():
            if str(header).lower() in {"host", "content-length"}:
                raise CollectionError(f"managed header is not allowed: {header}")
            variable_name = str(variable)
            secret = environment.get(variable_name)
            if not secret:
                raise CollectionError(
                    f"required environment variable is missing: {variable_name}"
                )
            if "\r" in secret or "\n" in secret:
                raise CollectionError(f"header contains a line break: {header}")
            headers[str(header)] = secret
        for header, content in value.get("static_headers", {}).items():
            if str(header).lower() in {
                "authorization",
                "cookie",
                "proxy-authorization",
                "host",
                "content-length",
            }:
                raise CollectionError(
                    f"sensitive or managed header must use an environment binding: {header}"
                )
            header_value = str(content)
            if "\r" in header_value or "\n" in header_value:
                raise CollectionError(f"header contains a line break: {header}")
            headers[str(header)] = header_value
        return cls(
            principal=str(value["principal"]),
            role=str(value.get("role", "user")),
            headers=headers,
            tenant=(str(value["tenant"]) if value.get("tenant") is not None else None),
            owned_resource_ids=(
                frozenset(str(item) for item in value.get("owned_resource_ids", []))
                if "owned_resource_ids" in value
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class CollectorLimits:
    max_requests: int = 100
    max_body_bytes: int = 1_000_000
    timeout_seconds: float = 10.0


class EvidenceCollector:
    """Bounded GET/HEAD/OPTIONS collector for an explicitly authorized scope."""

    def __init__(
        self,
        policy: ScopePolicy,
        limits: CollectorLimits | None = None,
        *,
        opener: Any | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ):
        self.policy = policy
        self.limits = limits or CollectorLimits()
        self.opener = opener or urllib.request.build_opener(_NoRedirect())
        self.clock = clock
        self.sleeper = sleeper
        self._last_request_at: dict[str, float] = {}

    def collect_matrix(
        self,
        requests: Iterable[RequestSpec],
        profiles: Iterable[SessionProfile],
    ) -> list[Observation]:
        request_list = list(requests)
        profile_list = list(profiles)
        total = len(request_list) * len(profile_list)
        if total > self.limits.max_requests:
            raise CollectionError(
                f"request matrix exceeds budget: {total}>{self.limits.max_requests}"
            )
        return [
            self.collect_one(spec, profile)
            for spec in request_list
            for profile in profile_list
        ]

    def collect_one(
        self,
        spec: RequestSpec,
        profile: SessionProfile,
    ) -> Observation:
        method = spec.method.upper()
        if method not in SAFE_METHODS:
            raise ScopeViolation(
                "collector executes read-only methods only; model state changes offline"
            )
        canonical, rule = self.policy.authorized_rule(
            spec.url,
            method,
            active=True,
        )
        self._rate_limit(rule.pattern, rule.max_rps)
        headers = {
            "Accept": "application/json, text/plain;q=0.8, */*;q=0.1",
            "User-Agent": "BARQ-CRS/0.2 authorized-security-research",
            **dict(profile.headers),
        }
        request = urllib.request.Request(canonical, headers=headers, method=method)
        started = self.clock()
        try:
            response = self.opener.open(request, timeout=self.limits.timeout_seconds)
            status = int(response.status)
            content_type = response.headers.get("Content-Type", "")
            raw = response.read(self.limits.max_body_bytes + 1)
        except urllib.error.HTTPError as error:
            status = int(error.code)
            content_type = error.headers.get("Content-Type", "")
            raw = error.read(self.limits.max_body_bytes + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise CollectionError(f"request failed: {type(error).__name__}") from error
        latency_ms = round((self.clock() - started) * 1000, 2)
        truncated = len(raw) > self.limits.max_body_bytes
        raw = raw[: self.limits.max_body_bytes]
        body = self._decode_body(raw, content_type)
        tags = (*spec.tags, "live-read-only", *(('truncated',) if truncated else ()))
        owns_resource = spec.owns_resource
        if spec.resource_id is not None and profile.owned_resource_ids is not None:
            owns_resource = spec.resource_id in profile.owned_resource_ids
        return Observation(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            method=method,
            url=canonical,
            route=spec.route or urlsplit(canonical).path,
            principal=profile.principal,
            role=profile.role,
            status=status,
            body=body,
            resource_id=spec.resource_id,
            owns_resource=owns_resource,
            principal_tenant=profile.tenant,
            resource_tenant=spec.resource_tenant,
            latency_ms=latency_ms,
            tags=tags,
        )

    def _rate_limit(self, key: str, max_rps: float) -> None:
        if max_rps <= 0:
            raise CollectionError("max_rps must be greater than zero")
        interval = 1.0 / max_rps
        now = self.clock()
        previous = self._last_request_at.get(key)
        if previous is not None and now - previous < interval:
            self.sleeper(interval - (now - previous))
            now = self.clock()
        self._last_request_at[key] = now

    @staticmethod
    def _decode_body(raw: bytes, content_type: str) -> Any:
        text = raw.decode("utf-8", errors="replace")
        if "json" in content_type.lower() or text.lstrip().startswith(("{", "[")):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass
        return text
