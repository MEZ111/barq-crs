from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

from .models import Observation


class TrafficFormatError(ValueError):
    pass


def _body(raw: bytes, content_type: str = "") -> Any:
    text = raw.decode("utf-8", errors="replace")
    if "json" in content_type.lower() or text.lstrip().startswith(("{", "[")):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    return text


def _http_body(message: bytes) -> tuple[bytes, str]:
    head, separator, body = message.partition(b"\r\n\r\n")
    if not separator:
        head, separator, body = message.partition(b"\n\n")
    content_type = ""
    for line in head.decode("latin-1", errors="ignore").splitlines():
        if line.lower().startswith("content-type:"):
            content_type = line.split(":", 1)[1].strip()
    return body if separator else b"", content_type


class HarIngestor:
    """Converts a browser/Burp HAR into BARQ observations without retaining headers."""

    def ingest(
        self,
        document: dict[str, Any],
        *,
        principal: str,
        role: str,
        tenant: str | None = None,
    ) -> list[Observation]:
        try:
            entries: Iterable[dict[str, Any]] = document["log"]["entries"]
        except (KeyError, TypeError) as error:
            raise TrafficFormatError("invalid HAR: log.entries is required") from error
        observations = []
        for entry in entries:
            request = entry.get("request", {})
            response = entry.get("response", {})
            url = str(request.get("url", ""))
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            content = response.get("content", {})
            text = str(content.get("text", ""))
            if content.get("encoding") == "base64":
                try:
                    raw = base64.b64decode(text, validate=True)
                except (ValueError, binascii.Error) as error:
                    raise TrafficFormatError("invalid base64 response in HAR") from error
            else:
                raw = text.encode()
            annotations = entry.get("_barq", {})
            observations.append(
                Observation(
                    timestamp=str(
                        entry.get("startedDateTime")
                        or datetime.now(timezone.utc).isoformat()
                    ),
                    method=str(request.get("method", "GET")).upper(),
                    url=url,
                    route=str(annotations.get("route") or parsed.path or "/"),
                    principal=principal,
                    role=role,
                    status=int(response.get("status", 0)),
                    body=_body(raw, str(content.get("mimeType", ""))),
                    resource_id=(
                        str(annotations["resource_id"])
                        if annotations.get("resource_id") is not None
                        else None
                    ),
                    owns_resource=annotations.get("owns_resource"),
                    principal_tenant=tenant,
                    resource_tenant=annotations.get("resource_tenant"),
                    latency_ms=(
                        float(entry["time"])
                        if entry.get("time") is not None
                        else None
                    ),
                    tags=("har",),
                )
            )
        return observations

    def load(
        self,
        path: str | Path,
        *,
        principal: str,
        role: str,
        tenant: str | None = None,
    ) -> list[Observation]:
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise TrafficFormatError("could not read HAR") from error
        return self.ingest(document, principal=principal, role=role, tenant=tenant)


class BurpXmlIngestor:
    """Converts Burp Suite XML history exports into BARQ observations."""

    def ingest(
        self,
        text: str,
        *,
        principal: str,
        role: str,
        tenant: str | None = None,
    ) -> list[Observation]:
        try:
            root = ET.fromstring(text)
        except ET.ParseError as error:
            raise TrafficFormatError("invalid Burp XML") from error
        observations = []
        for item in root.findall(".//item"):
            url = item.findtext("url", "")
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            response_node = item.find("response")
            encoded = response_node is not None and response_node.get("base64") == "true"
            response_text = response_node.text if response_node is not None else ""
            try:
                message = (
                    base64.b64decode(response_text or "", validate=True)
                    if encoded
                    else (response_text or "").encode("latin-1", errors="replace")
                )
            except (ValueError, binascii.Error) as error:
                raise TrafficFormatError("invalid base64 response in Burp XML") from error
            response_body, content_type = _http_body(message)
            observations.append(
                Observation(
                    timestamp=item.findtext("time", "")
                    or datetime.now(timezone.utc).isoformat(),
                    method=item.findtext("method", "GET").upper(),
                    url=url,
                    route=parsed.path or "/",
                    principal=principal,
                    role=role,
                    status=int(item.findtext("status", "0")),
                    body=_body(response_body, content_type),
                    principal_tenant=tenant,
                    tags=("burp-xml",),
                )
            )
        return observations

    def load(
        self,
        path: str | Path,
        *,
        principal: str,
        role: str,
        tenant: str | None = None,
    ) -> list[Observation]:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as error:
            raise TrafficFormatError("could not read Burp XML") from error
        return self.ingest(text, principal=principal, role=role, tenant=tenant)
