from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
import re
import struct
from typing import Iterable
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
import zipfile

from .models import Candidate, Evidence


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
TEXT_SUFFIXES = {
    ".java",
    ".kt",
    ".smali",
    ".xml",
    ".json",
    ".js",
    ".properties",
    ".txt",
    ".cfg",
    ".conf",
}
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
MAX_STRING_SCAN = 2_000_000
NO_INDEX = 0xFFFFFFFF
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
UTF8_FLAG = 0x00000100


def _fp(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode()).hexdigest()


def _safe_name(value: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", "?", value.replace("\\", "/").lstrip("/"))


def _android(element: ET.Element, name: str) -> str | None:
    return element.get(f"{ANDROID_NS}{name}")


def _truthy(value: str | None) -> bool:
    return str(value).lower() == "true"


def _printable_strings(raw: bytes) -> str:
    """Extract bounded ASCII/UTF-16 strings from opaque DEX or binary AXML."""
    sample = raw[:MAX_STRING_SCAN]
    ascii_values = (match.decode("utf-8", "ignore") for match in re.findall(rb"[\x20-\x7e]{6,}", sample))
    utf16_values = (
        match.decode("utf-16le", "ignore")
        for match in re.findall(rb"(?:[\x20-\x7e]\x00){6,}", sample)
    )
    return "\n".join((*ascii_values, *utf16_values))


class BinaryXmlError(ValueError):
    pass


def _chunk(raw: bytes, offset: int) -> tuple[int, int, int]:
    if offset < 0 or offset + 8 > len(raw):
        raise BinaryXmlError("truncated binary XML chunk header")
    chunk_type, header_size, size = struct.unpack_from("<HHI", raw, offset)
    if header_size < 8 or size < header_size or offset + size > len(raw):
        raise BinaryXmlError("invalid binary XML chunk bounds")
    return chunk_type, header_size, size


def _length8(raw: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(raw):
        raise BinaryXmlError("truncated UTF-8 string length")
    value = raw[offset]
    if value & 0x80:
        if offset + 1 >= len(raw):
            raise BinaryXmlError("truncated UTF-8 string length")
        return ((value & 0x7F) << 8) | raw[offset + 1], offset + 2
    return value, offset + 1


def _length16(raw: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(raw):
        raise BinaryXmlError("truncated UTF-16 string length")
    value = struct.unpack_from("<H", raw, offset)[0]
    if value & 0x8000:
        if offset + 4 > len(raw):
            raise BinaryXmlError("truncated UTF-16 string length")
        tail = struct.unpack_from("<H", raw, offset + 2)[0]
        return ((value & 0x7FFF) << 16) | tail, offset + 4
    return value, offset + 2


def _string_pool(raw: bytes, offset: int) -> tuple[list[str], int]:
    chunk_type, header_size, size = _chunk(raw, offset)
    if chunk_type != RES_STRING_POOL_TYPE or header_size < 28:
        raise BinaryXmlError("invalid binary XML string pool")
    string_count, _, flags, strings_start, _ = struct.unpack_from("<IIIII", raw, offset + 8)
    if string_count > 1_000_000 or header_size + string_count * 4 > size:
        raise BinaryXmlError("invalid binary XML string count")
    strings: list[str] = []
    for index in range(string_count):
        relative = struct.unpack_from("<I", raw, offset + header_size + index * 4)[0]
        cursor = offset + strings_start + relative
        if cursor >= offset + size:
            raise BinaryXmlError("binary XML string offset is outside its pool")
        if flags & UTF8_FLAG:
            _, cursor = _length8(raw, cursor)
            byte_length, cursor = _length8(raw, cursor)
            end = cursor + byte_length
            if end > offset + size:
                raise BinaryXmlError("truncated UTF-8 string")
            strings.append(raw[cursor:end].decode("utf-8", "replace"))
        else:
            length, cursor = _length16(raw, cursor)
            end = cursor + length * 2
            if end > offset + size:
                raise BinaryXmlError("truncated UTF-16 string")
            strings.append(raw[cursor:end].decode("utf-16le", "replace"))
    return strings, size


def _pool_value(strings: list[str], index: int) -> str | None:
    if index == NO_INDEX:
        return None
    if index < 0 or index >= len(strings):
        raise BinaryXmlError("binary XML string index is out of range")
    return strings[index]


def _typed_value(strings: list[str], data_type: int, data: int) -> str:
    if data_type == 0x03:
        return _pool_value(strings, data) or ""
    if data_type == 0x12:
        return "true" if data else "false"
    if data_type == 0x10:
        return str(data if data < 0x80000000 else data - 0x100000000)
    if data_type == 0x11:
        return f"0x{data:08x}"
    if data_type == 0x01:
        return f"@0x{data:08x}"
    if data_type == 0x02:
        return f"?0x{data:08x}"
    return f"0x{data:08x}"


def decode_binary_manifest(raw: bytes) -> ET.Element:
    """Decode the structural subset of Android's binary XML format we need."""
    chunk_type, header_size, total_size = _chunk(raw, 0)
    if chunk_type != RES_XML_TYPE:
        raise BinaryXmlError("not an Android binary XML document")
    strings: list[str] | None = None
    stack: list[ET.Element] = []
    root: ET.Element | None = None
    offset = header_size
    while offset < total_size:
        current_type, current_header, current_size = _chunk(raw, offset)
        if current_type == RES_STRING_POOL_TYPE:
            strings, _ = _string_pool(raw, offset)
        elif current_type == RES_XML_START_ELEMENT_TYPE:
            if strings is None or current_header < 36:
                raise BinaryXmlError("start element appeared before a valid string pool")
            extension = offset + 16
            namespace_index, name_index = struct.unpack_from("<II", raw, extension)
            attribute_start, attribute_size, attribute_count = struct.unpack_from(
                "<HHH", raw, extension + 8
            )
            if attribute_size < 20 or attribute_count > 65_535:
                raise BinaryXmlError("invalid binary XML attribute table")
            tag = _pool_value(strings, name_index)
            if not tag:
                raise BinaryXmlError("binary XML element has no name")
            namespace = _pool_value(strings, namespace_index)
            element = ET.Element(f"{{{namespace}}}{tag}" if namespace else tag)
            first_attribute = extension + attribute_start
            for index in range(attribute_count):
                cursor = first_attribute + index * attribute_size
                if cursor + 20 > offset + current_size:
                    raise BinaryXmlError("truncated binary XML attribute")
                attr_namespace, attr_name, raw_value = struct.unpack_from("<III", raw, cursor)
                value_size, _, value_type, value_data = struct.unpack_from("<HBBI", raw, cursor + 12)
                if value_size < 8:
                    raise BinaryXmlError("invalid binary XML typed value")
                name = _pool_value(strings, attr_name)
                if not name:
                    raise BinaryXmlError("binary XML attribute has no name")
                namespace = _pool_value(strings, attr_namespace)
                value = _pool_value(strings, raw_value)
                if value is None:
                    value = _typed_value(strings, value_type, value_data)
                qname = f"{{{namespace}}}{name}" if namespace else name
                element.set(qname, value)
            if stack:
                stack[-1].append(element)
            elif root is None:
                root = element
            else:
                raise BinaryXmlError("multiple binary XML root elements")
            stack.append(element)
        elif current_type == RES_XML_END_ELEMENT_TYPE:
            if not stack:
                raise BinaryXmlError("unbalanced binary XML end element")
            stack.pop()
        offset += current_size
    if root is None or stack:
        raise BinaryXmlError("incomplete Android binary XML document")
    return root


@dataclass(frozen=True, slots=True)
class MobileInventory:
    artifact: str
    artifact_kind: str
    file_count: int
    dex_files: tuple[str, ...]
    native_libraries: tuple[str, ...]
    certificate_entries: tuple[str, ...]
    manifest_format: str
    deep_links: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class MobileAnalysis:
    inventory: MobileInventory
    candidates: tuple[Candidate, ...]

    def to_dict(self) -> dict:
        return {
            "inventory": self.inventory.to_dict(),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


@dataclass(frozen=True, slots=True)
class _Artifact:
    names: tuple[str, ...]
    contents: dict[str, bytes]
    warnings: tuple[str, ...]
    kind: str


class AndroidArtifactAnalyzer:
    """Bounded static analysis for an APK or a locally decoded Android tree.

    APK files are inspected in place and never extracted. Findings contain only
    structural metadata and one-way fingerprints; embedded secret values are
    deliberately excluded from every result.
    """

    def __init__(
        self,
        *,
        max_entries: int = 20_000,
        max_total_bytes: int = 256 * 1024 * 1024,
        max_entry_bytes: int = 16 * 1024 * 1024,
        max_compression_ratio: float = 200.0,
    ):
        self.max_entries = max_entries
        self.max_total_bytes = max_total_bytes
        self.max_entry_bytes = max_entry_bytes
        self.max_compression_ratio = max_compression_ratio

    def analyze(self, path: str | Path) -> MobileAnalysis:
        source = Path(path)
        artifact = self._read(source)
        manifest_raw = artifact.contents.get("AndroidManifest.xml")
        manifest_format = "missing"
        manifest_root: ET.Element | None = None
        warnings = list(artifact.warnings)
        if manifest_raw is not None:
            try:
                text = manifest_raw.decode("utf-8-sig")
                manifest_root = ET.fromstring(text)
                manifest_format = "xml"
            except (UnicodeDecodeError, ET.ParseError):
                try:
                    manifest_root = decode_binary_manifest(manifest_raw)
                    manifest_format = "binary-axml"
                except BinaryXmlError as exc:
                    manifest_format = "binary-axml-unparsed"
                    warnings.append(f"Could not decode binary AndroidManifest.xml: {exc}")

        candidates: list[Candidate] = []
        deep_links: set[str] = set()
        if manifest_root is not None:
            manifest_candidates, deep_links = self._manifest_findings(manifest_root)
            candidates.extend(manifest_candidates)
        candidates.extend(self._network_config_findings(artifact.contents))
        candidates.extend(self._code_findings(artifact.contents))

        names = artifact.names
        inventory = MobileInventory(
            artifact=str(source),
            artifact_kind=artifact.kind,
            file_count=len(names),
            dex_files=tuple(name for name in names if re.fullmatch(r"classes\d*\.dex", Path(name).name)),
            native_libraries=tuple(name for name in names if name.endswith(".so")),
            certificate_entries=tuple(
                name
                for name in names
                if name.upper().startswith("META-INF/")
                and Path(name).suffix.upper() in {".RSA", ".DSA", ".EC", ".SF", ".MF"}
            ),
            manifest_format=manifest_format,
            deep_links=tuple(sorted(deep_links)),
            warnings=tuple(dict.fromkeys(warnings)),
        )
        unique = {candidate.id: candidate for candidate in candidates}
        ordered = tuple(sorted(unique.values(), key=lambda item: (item.target, item.kind, item.id)))
        return MobileAnalysis(inventory, ordered)

    def _read(self, source: Path) -> _Artifact:
        if not source.exists():
            raise FileNotFoundError(source)
        if source.is_dir():
            return self._read_directory(source)
        if not zipfile.is_zipfile(source):
            raise ValueError("mobile input must be an APK/ZIP or decoded Android directory")
        return self._read_archive(source)

    def _read_archive(self, source: Path) -> _Artifact:
        warnings: list[str] = []
        contents: dict[str, bytes] = {}
        names: list[str] = []
        with zipfile.ZipFile(source) as archive:
            infos = sorted((item for item in archive.infolist() if not item.is_dir()), key=lambda item: item.filename)
            if len(infos) > self.max_entries:
                raise ValueError(f"archive entry limit exceeded: {len(infos)} > {self.max_entries}")
            total = sum(item.file_size for item in infos)
            if total > self.max_total_bytes:
                raise ValueError(f"archive expansion limit exceeded: {total} bytes")
            for info in infos:
                name = _safe_name(info.filename)
                names.append(name)
                if name != info.filename.replace("\\", "/").lstrip("/"):
                    warnings.append(f"Sanitized control characters in archive entry: {name}")
                if info.flag_bits & 0x1:
                    warnings.append(f"Skipped encrypted entry: {name}")
                    continue
                compressed = max(1, info.compress_size)
                ratio = info.file_size / compressed
                if info.file_size > self.max_entry_bytes:
                    warnings.append(f"Skipped oversized entry: {name}")
                    continue
                if info.file_size > 1_000_000 and ratio > self.max_compression_ratio:
                    warnings.append(f"Skipped suspicious compression ratio: {name}")
                    continue
                if self._interesting(name):
                    if name in contents:
                        warnings.append(f"Skipped duplicate normalized entry: {name}")
                        continue
                    contents[name] = archive.read(info)
        return _Artifact(tuple(names), contents, tuple(warnings), "apk")

    def _read_directory(self, source: Path) -> _Artifact:
        paths = sorted(path for path in source.rglob("*") if path.is_file() or path.is_symlink())
        if len(paths) > self.max_entries:
            raise ValueError(f"directory entry limit exceeded: {len(paths)} > {self.max_entries}")
        contents: dict[str, bytes] = {}
        warnings: list[str] = []
        total = 0
        names: list[str] = []
        for path in paths:
            relative = path.relative_to(source).as_posix()
            names.append(relative)
            if path.is_symlink():
                warnings.append(f"Skipped symbolic link: {relative}")
                continue
            try:
                size = path.stat().st_size
            except OSError:
                warnings.append(f"Could not stat entry: {relative}")
                continue
            total += size
            if total > self.max_total_bytes:
                raise ValueError(f"directory size limit exceeded: {total} bytes")
            if size > self.max_entry_bytes:
                warnings.append(f"Skipped oversized entry: {relative}")
                continue
            if self._interesting(relative):
                try:
                    contents[relative] = path.read_bytes()
                except OSError:
                    warnings.append(f"Could not read entry: {relative}")
        return _Artifact(tuple(names), contents, tuple(warnings), "decoded-directory")

    @staticmethod
    def _interesting(name: str) -> bool:
        path = Path(name)
        return (
            name == "AndroidManifest.xml"
            or path.suffix.lower() in TEXT_SUFFIXES | {".dex"}
            or name.startswith("res/xml/")
        )

    def _manifest_findings(self, root: ET.Element) -> tuple[list[Candidate], set[str]]:
        findings: list[Candidate] = []
        deep_links: set[str] = set()
        application = root.find("application")
        if application is None:
            return findings, deep_links

        settings = (
            (
                "debuggable",
                "debuggable-release-build",
                "Release application is marked debuggable",
                "high",
                0.9,
                "Disable android:debuggable in production variants and verify the signed release manifest.",
            ),
            (
                "allowBackup",
                "application-backup-enabled",
                "Application data backup is explicitly enabled",
                "medium",
                0.62,
                "Disable backup for sensitive data or define strict backup/data-extraction rules.",
            ),
            (
                "usesCleartextTraffic",
                "cleartext-traffic-enabled",
                "Application explicitly permits cleartext network traffic",
                "medium",
                0.72,
                "Require TLS and narrow any network security exceptions to development builds.",
            ),
        )
        for attribute, kind, title, severity, impact, remediation in settings:
            if _truthy(_android(application, attribute)):
                findings.append(
                    self._candidate(
                        kind=kind,
                        title=title,
                        target="AndroidManifest.xml:1::application",
                        severity=severity,
                        confidence=0.98,
                        impact=impact,
                        evidence_kind="manifest-attribute",
                        summary=f"android:{attribute} is explicitly true",
                        material=(attribute, "true"),
                        metadata={"attribute": attribute, "value": True},
                        remediation=remediation,
                        next_step="Confirm the merged release manifest and reproduce only on an emulator or owned test device.",
                    )
                )

        app_permission = _android(application, "permission")
        for tag in COMPONENT_TAGS:
            for component in application.findall(tag):
                name = _android(component, "name") or "<unnamed>"
                explicit = _android(component, "exported")
                intent_filters = component.findall("intent-filter")
                exported = _truthy(explicit) or (explicit is None and bool(intent_filters))
                component_permission = (
                    _android(component, "permission")
                    or _android(component, "readPermission")
                    or _android(component, "writePermission")
                    or app_permission
                )
                for intent_filter in intent_filters:
                    actions = {_android(node, "name") for node in intent_filter.findall("action")}
                    categories = {_android(node, "name") for node in intent_filter.findall("category")}
                    for data in intent_filter.findall("data"):
                        scheme = _android(data, "scheme")
                        host = _android(data, "host")
                        path = _android(data, "pathPrefix") or _android(data, "path") or ""
                        if scheme:
                            deep_links.add(f"{scheme}://{host or '*'}{path}")
                    browsable = "android.intent.category.BROWSABLE" in categories
                    view = "android.intent.action.VIEW" in actions
                    if exported and browsable and view and not _truthy(_android(intent_filter, "autoVerify")):
                        findings.append(
                            self._candidate(
                                kind="unverified-deep-link-handler",
                                title="Exported deep-link handler is not origin-verified",
                                target=f"AndroidManifest.xml:1::{name}",
                                severity="low",
                                confidence=0.88,
                                impact=0.48,
                                evidence_kind="intent-filter",
                                summary="Exported VIEW/BROWSABLE intent filter has no verified app-link binding",
                                material=(tag, name, "deep-link"),
                                metadata={"component": name, "component_type": tag},
                                remediation="Use verified HTTPS App Links and validate every inbound route and parameter.",
                                next_step="Exercise the route on an emulator with controlled benign values and confirm destination validation.",
                            )
                        )
                if exported and not component_permission:
                    severity = "high" if tag == "provider" else "medium"
                    findings.append(
                        self._candidate(
                            kind="exported-component-without-permission",
                            title=f"Exported Android {tag} has no manifest permission boundary",
                            target=f"AndroidManifest.xml:1::{name}",
                            severity=severity,
                            confidence=0.9 if explicit is not None else 0.72,
                            impact=0.86 if tag == "provider" else 0.66,
                            evidence_kind="component-boundary",
                            summary="Component is externally reachable and no component/application permission is declared",
                            material=(tag, name, explicit, len(intent_filters)),
                            metadata={
                                "component": name,
                                "component_type": tag,
                                "explicit_exported": explicit,
                                "intent_filter_count": len(intent_filters),
                            },
                            remediation="Set android:exported=false unless required; otherwise enforce a signature permission and runtime authorization.",
                            next_step="Confirm component reachability and data exposure on an emulator using a researcher-owned test build.",
                        )
                    )
        return findings, deep_links

    def _network_config_findings(self, contents: dict[str, bytes]) -> list[Candidate]:
        findings = []
        for name, raw in sorted(contents.items()):
            if not name.startswith("res/xml/") or not name.endswith(".xml"):
                continue
            text = raw.decode("utf-8", "ignore")
            try:
                root = ET.fromstring(text)
            except ET.ParseError:
                continue

            release_user_ca = False

            def walk(node: ET.Element, in_debug: bool = False) -> None:
                nonlocal release_user_ca
                local = node.tag.rsplit("}", 1)[-1]
                in_debug = in_debug or local == "debug-overrides"
                if local == "certificates" and node.get("src") == "user" and not in_debug:
                    release_user_ca = True
                for child in node:
                    walk(child, in_debug)

            walk(root)
            if release_user_ca:
                match = re.search(r"<certificates\s+[^>]*src\s*=\s*[\"']user[\"']", text, re.I)
                line = text.count("\n", 0, match.start()) + 1 if match else 1
                findings.append(
                    self._candidate(
                        kind="user-ca-trust",
                        title="Network security configuration trusts user-installed certificate authorities",
                        target=f"{name}:{line}::certificates",
                        severity="medium",
                        confidence=0.94,
                        impact=0.7,
                        evidence_kind="network-security-config",
                        summary="A trust anchor references the user certificate store",
                        material=(name, line, "user-ca"),
                        metadata={"file": name, "line": line},
                        remediation="Remove user CA trust from release configuration or isolate it under debug-overrides.",
                        next_step="Confirm whether the referenced XML is active in the merged release manifest.",
                    )
                )
        return findings

    def _code_findings(self, contents: dict[str, bytes]) -> list[Candidate]:
        findings: list[Candidate] = []
        rules = (
            (
                "webview-javascript-bridge",
                "WebView enables JavaScript and exposes a native bridge",
                "high",
                0.84,
                (r"setJavaScriptEnabled\s*\(\s*true\s*\)", r"addJavascriptInterface\s*\("),
                "Require trusted origins, minimize the bridge surface, and avoid exposing it to untrusted content.",
            ),
            (
                "webview-universal-file-access",
                "WebView enables universal access from file URLs",
                "high",
                0.88,
                (r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)",),
                "Disable universal file URL access and serve trusted content from a constrained HTTPS origin.",
            ),
            (
                "webview-file-access",
                "WebView enables file access from file URLs",
                "medium",
                0.67,
                (r"setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)",),
                "Disable file URL access or strictly separate local and network content.",
            ),
            (
                "tls-error-bypass",
                "TLS error handler appears to continue after certificate failure",
                "critical",
                0.95,
                (r"onReceivedSslError\s*\(", r"\.proceed\s*\("),
                "Cancel on certificate errors and rely on platform trust validation.",
            ),
            (
                "permissive-hostname-verifier",
                "Custom hostname verifier appears to accept every hostname",
                "high",
                0.9,
                (r"HostnameVerifier", r"(?:return\s+true|->\s*true)"),
                "Remove permissive hostname verification and use the platform verifier.",
            ),
            (
                "world-readable-storage",
                "Application references world-readable or world-writeable storage mode",
                "high",
                0.82,
                (r"MODE_WORLD_(?:READABLE|WRITEABLE)",),
                "Use private app storage and explicit, least-privilege content sharing.",
            ),
            (
                "webview-debugging-enabled",
                "WebView remote debugging is explicitly enabled",
                "medium",
                0.6,
                (r"setWebContentsDebuggingEnabled\s*\(\s*true\s*\)",),
                "Disable WebView debugging in production builds.",
            ),
        )
        secret_rules = (
            ("aws-access-key", rb"AKIA[0-9A-Z]{16}"),
            ("google-api-key", rb"AIza[0-9A-Za-z_-]{35}"),
            ("private-key", rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            ("github-token", rb"gh[pousr]_[A-Za-z0-9]{30,255}"),
        )

        for name, raw in sorted(contents.items()):
            if name == "AndroidManifest.xml":
                continue
            if name.endswith(".dex"):
                text = _printable_strings(raw)
            else:
                text = raw.decode("utf-8", "ignore")
            for kind, title, severity, impact, patterns, remediation in rules:
                matches = [re.search(pattern, text, re.I | re.S) for pattern in patterns]
                if not all(matches):
                    continue
                first = min(match.start() for match in matches if match is not None)
                line = text.count("\n", 0, first) + 1
                findings.append(
                    self._candidate(
                        kind=kind,
                        title=title,
                        target=f"{name}:{line}::static-analysis",
                        severity=severity,
                        confidence=0.94 if len(patterns) > 1 else 0.88,
                        impact=impact,
                        evidence_kind="code-pattern",
                        summary="Required code-pattern combination appears in one artifact entry",
                        material=(name, kind, *(match.group(0)[:32] for match in matches if match)),
                        metadata={"file": name, "line": line, "signals": len(patterns)},
                        remediation=remediation,
                        next_step="Trace the call path in the decoded source and reproduce with benign inputs on an emulator.",
                    )
                )
            for secret_kind, pattern in secret_rules:
                match = re.search(pattern, raw)
                if match is None:
                    continue
                line = raw[: match.start()].count(b"\n") + 1
                secret_fingerprint = sha256(match.group(0)).hexdigest()
                findings.append(
                    self._candidate(
                        kind="embedded-credential-material",
                        title="Potential credential material is embedded in the mobile artifact",
                        target=f"{name}:{line}::secret-fingerprint",
                        severity="critical" if secret_kind == "private-key" else "high",
                        confidence=0.97,
                        impact=0.93,
                        evidence_kind="secret-fingerprint",
                        summary=f"Detected {secret_kind}; raw value intentionally withheld",
                        material=(name, secret_kind, secret_fingerprint),
                        metadata={
                            "file": name,
                            "line": line,
                            "secret_type": secret_kind,
                            "value_sha256": secret_fingerprint,
                        },
                        remediation="Revoke and rotate the credential, remove it from the client, and use a server-side secret boundary.",
                        next_step="Verify ownership and validity through the provider console without printing or transmitting the value.",
                    )
                )
            findings.extend(self._cleartext_endpoints(name, text))
        return findings

    def _cleartext_endpoints(self, name: str, text: str) -> Iterable[Candidate]:
        seen: set[str] = set()
        for match in re.finditer(r"http://[A-Za-z0-9._-]+(?::\d+)?(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]*)?", text):
            url = match.group(0).rstrip(".,);\"'")
            parsed = urlsplit(url)
            host = (parsed.hostname or "").lower()
            if not host or host in {"localhost", "127.0.0.1", "10.0.2.2"} or host.endswith(".test"):
                continue
            if host in seen:
                continue
            seen.add(host)
            line = text.count("\n", 0, match.start()) + 1
            yield self._candidate(
                kind="cleartext-endpoint-reference",
                title="Mobile artifact references a non-local cleartext HTTP endpoint",
                target=f"{name}:{line}::endpoint",
                severity="low",
                confidence=0.9,
                impact=0.52,
                evidence_kind="endpoint-inventory",
                summary="A non-local endpoint uses HTTP rather than HTTPS",
                material=(name, host, parsed.port),
                metadata={"file": name, "line": line, "host": host, "port": parsed.port},
                remediation="Migrate the endpoint to HTTPS and enforce cleartext blocking in the release configuration.",
                next_step="Confirm whether the endpoint is reachable from the release build and whether sensitive data traverses it.",
            )
            if len(seen) >= 10:
                return

    @staticmethod
    def _candidate(
        *,
        kind: str,
        title: str,
        target: str,
        severity: str,
        confidence: float,
        impact: float,
        evidence_kind: str,
        summary: str,
        material: tuple[object, ...],
        metadata: dict,
        remediation: str,
        next_step: str,
    ) -> Candidate:
        return Candidate(
            engine="android-static",
            kind=kind,
            title=title,
            target=target,
            severity=severity,
            confidence=confidence,
            impact=impact,
            novelty=0.76,
            reproducibility=1.0,
            evidence=(Evidence(evidence_kind, summary, _fp(*material), metadata),),
            remediation_hint=remediation,
            safe_next_step=next_step,
        )
