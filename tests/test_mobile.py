import json
from pathlib import Path
import struct
import zipfile

import pytest

from barq_crs.mobile import AndroidArtifactAnalyzer, decode_binary_manifest


ANDROID_URI = "http://schemas.android.com/apk/res/android"
NO_INDEX = 0xFFFFFFFF


def _pad4(value: bytes) -> bytes:
    return value + b"\0" * ((-len(value)) % 4)


def _string_pool(strings: list[str]) -> bytes:
    offsets = []
    data = bytearray()
    for value in strings:
        encoded = value.encode()
        offsets.append(len(data))
        data.extend((len(value), len(encoded)))
        data.extend(encoded)
        data.append(0)
    body = _pad4(bytes(data))
    start = 28 + 4 * len(strings)
    size = start + len(body)
    header = struct.pack("<HHI", 0x0001, 28, size)
    metadata = struct.pack("<IIIII", len(strings), 0, 0x100, start, 0)
    return header + metadata + struct.pack(f"<{len(strings)}I", *offsets) + body


def _start(strings: list[str], tag: str, attributes=()) -> bytes:
    index = {value: position for position, value in enumerate(strings)}
    attribute_values = []
    for namespace, name, value_type, value in attributes:
        data = index[value] if value_type == 0x03 else int(value)
        attribute_values.append(
            struct.pack(
                "<IIIHBBI",
                index[namespace] if namespace else NO_INDEX,
                index[name],
                NO_INDEX,
                8,
                0,
                value_type,
                data,
            )
        )
    size = 36 + 20 * len(attribute_values)
    node = struct.pack("<HHIII", 0x0102, 36, size, 1, NO_INDEX)
    extension = struct.pack(
        "<IIHHHHHH",
        NO_INDEX,
        index[tag],
        20,
        20,
        len(attribute_values),
        0,
        0,
        0,
    )
    return node + extension + b"".join(attribute_values)


def _end(strings: list[str], tag: str) -> bytes:
    index = {value: position for position, value in enumerate(strings)}
    return struct.pack("<HHIIIII", 0x0103, 24, 24, 1, NO_INDEX, NO_INDEX, index[tag])


def binary_manifest() -> bytes:
    strings = ["manifest", "application", ANDROID_URI, "debuggable"]
    chunks = [
        _string_pool(strings),
        _start(strings, "manifest"),
        _start(strings, "application", ((ANDROID_URI, "debuggable", 0x12, 1),)),
        _end(strings, "application"),
        _end(strings, "manifest"),
    ]
    size = 8 + sum(len(chunk) for chunk in chunks)
    return struct.pack("<HHI", 0x0003, 8, size) + b"".join(chunks)


def manifest(extra_application="", component=""):
    return f'''<?xml version="1.0"?>
    <manifest xmlns:android="{ANDROID_URI}" package="test.app">
      <application {extra_application}>{component}</application>
    </manifest>'''


def test_analyzes_decoded_manifest_settings_and_component(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(
        manifest(
            'android:debuggable="true" android:usesCleartextTraffic="true"',
            '<provider android:name=".Data" android:exported="true" />',
        )
    )
    analysis = AndroidArtifactAnalyzer().analyze(tmp_path)
    kinds = {item.kind for item in analysis.candidates}
    assert {"debuggable-release-build", "cleartext-traffic-enabled", "exported-component-without-permission"} <= kinds


def test_extracts_deep_link_and_marks_unverified_handler(tmp_path):
    component = '''<activity android:name=".Route" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="owned.test" android:pathPrefix="/go" />
      </intent-filter>
    </activity>'''
    (tmp_path / "AndroidManifest.xml").write_text(manifest(component=component))
    analysis = AndroidArtifactAnalyzer().analyze(tmp_path)
    assert analysis.inventory.deep_links == ("https://owned.test/go",)
    assert any(item.kind == "unverified-deep-link-handler" for item in analysis.candidates)


def test_detects_webview_and_tls_pattern_combinations(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(manifest())
    source = tmp_path / "Unsafe.java"
    source.write_text(
        "setJavaScriptEnabled(true); addJavascriptInterface(x, \"B\"); "
        "onReceivedSslError(x); handler.proceed();"
    )
    kinds = {item.kind for item in AndroidArtifactAnalyzer().analyze(tmp_path).candidates}
    assert {"webview-javascript-bridge", "tls-error-bypass"} <= kinds


def test_embedded_secret_value_is_never_emitted(tmp_path):
    value = "AKIAABCDEFGHIJKLMNOP"
    (tmp_path / "AndroidManifest.xml").write_text(manifest())
    (tmp_path / "config.properties").write_text(f"access={value}")
    analysis = AndroidArtifactAnalyzer().analyze(tmp_path)
    finding = next(item for item in analysis.candidates if item.kind == "embedded-credential-material")
    assert finding.evidence[0].metadata["secret_type"] == "aws-access-key"
    assert len(finding.evidence[0].metadata["value_sha256"]) == 64
    assert value not in json.dumps(analysis.to_dict())


def test_user_ca_trust_inside_debug_overrides_is_not_reported(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(manifest())
    config = tmp_path / "res" / "xml"
    config.mkdir(parents=True)
    (config / "network.xml").write_text(
        '<network-security-config><debug-overrides><trust-anchors>'
        '<certificates src="user"/></trust-anchors></debug-overrides></network-security-config>'
    )
    kinds = {item.kind for item in AndroidArtifactAnalyzer().analyze(tmp_path).candidates}
    assert "user-ca-trust" not in kinds


def test_release_user_ca_trust_is_reported(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(manifest())
    config = tmp_path / "res" / "xml"
    config.mkdir(parents=True)
    (config / "network.xml").write_text(
        '<network-security-config><base-config><trust-anchors>'
        '<certificates src="user"/></trust-anchors></base-config></network-security-config>'
    )
    assert any(item.kind == "user-ca-trust" for item in AndroidArtifactAnalyzer().analyze(tmp_path).candidates)


def test_decodes_binary_android_manifest_without_third_party_dependency(tmp_path):
    apk = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest())
        archive.writestr("classes.dex", b"dex\n035\0fixture")
    analysis = AndroidArtifactAnalyzer().analyze(apk)
    assert analysis.inventory.manifest_format == "binary-axml"
    assert analysis.inventory.dex_files == ("classes.dex",)
    assert any(item.kind == "debuggable-release-build" for item in analysis.candidates)


def test_binary_decoder_rejects_truncated_input():
    with pytest.raises(ValueError):
        decode_binary_manifest(b"\x03\x00\x08\x00")


def test_apk_inventory_includes_native_and_signature_entries(tmp_path):
    apk = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest())
        archive.writestr("lib/arm64-v8a/libfixture.so", b"ELF")
        archive.writestr("META-INF/CERT.RSA", b"certificate")
    inventory = AndroidArtifactAnalyzer().analyze(apk).inventory
    assert inventory.native_libraries == ("lib/arm64-v8a/libfixture.so",)
    assert inventory.certificate_entries == ("META-INF/CERT.RSA",)


def test_archive_entry_limit_blocks_unbounded_input(tmp_path):
    apk = tmp_path / "many.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest())
        archive.writestr("one.txt", "1")
    with pytest.raises(ValueError, match="entry limit"):
        AndroidArtifactAnalyzer(max_entries=1).analyze(apk)


def test_oversized_entry_is_skipped_with_warning(tmp_path):
    apk = tmp_path / "large.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest())
        archive.writestr("large.txt", "A" * 100)
    analysis = AndroidArtifactAnalyzer(max_entry_bytes=80).analyze(apk)
    assert any("oversized entry" in warning for warning in analysis.inventory.warnings)


def test_candidate_ids_are_deterministic(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(manifest('android:debuggable="true"'))
    analyzer = AndroidArtifactAnalyzer()
    first = [item.id for item in analyzer.analyze(tmp_path).candidates]
    second = [item.id for item in analyzer.analyze(tmp_path).candidates]
    assert first == second


def test_rejects_non_archive_file(tmp_path):
    value = tmp_path / "not-an-apk.bin"
    value.write_bytes(b"not a zip")
    with pytest.raises(ValueError, match="APK/ZIP"):
        AndroidArtifactAnalyzer().analyze(value)
