import base64
import json

import pytest

from barq_crs.traffic import BurpXmlIngestor, HarIngestor, TrafficFormatError


def har_entry(text, encoding=None):
    content = {"text": text, "mimeType": "application/json"}
    if encoding:
        content["encoding"] = encoding
    return {
        "startedDateTime": "2026-09-11T00:00:00Z",
        "time": 12.5,
        "request": {"method": "GET", "url": "https://lab.test/users/7"},
        "response": {"status": 200, "content": content},
        "_barq": {
            "route": "/users/{id}",
            "resource_id": "7",
            "owns_resource": True,
            "resource_tenant": "red",
        },
    }


def test_har_ingests_annotations_and_json():
    observations = HarIngestor().ingest(
        {"log": {"entries": [har_entry('{"email":"owned@test"}')] }},
        principal="owner",
        role="user",
        tenant="red",
    )
    assert observations[0].route == "/users/{id}"
    assert observations[0].body == {"email": "owned@test"}
    assert observations[0].owns_resource is True


def test_har_decodes_base64():
    encoded = base64.b64encode(b'{"id":7}').decode()
    observation = HarIngestor().ingest(
        {"log": {"entries": [har_entry(encoded, "base64")]}},
        principal="owner",
        role="user",
    )[0]
    assert observation.body == {"id": 7}


def test_har_rejects_missing_entries():
    with pytest.raises(TrafficFormatError, match="log.entries"):
        HarIngestor().ingest({}, principal="x", role="user")


def test_har_skips_non_http_urls():
    entry = har_entry("{}")
    entry["request"]["url"] = "file:///tmp/a"
    assert HarIngestor().ingest(
        {"log": {"entries": [entry]}}, principal="x", role="user"
    ) == []


def test_burp_xml_ingests_response_body():
    message = base64.b64encode(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":7}"
    ).decode()
    xml = f"""<items><item><time>now</time><url>https://lab.test/users/7</url>
    <method>GET</method><status>200</status><response base64="true">{message}</response>
    </item></items>"""
    observation = BurpXmlIngestor().ingest(
        xml, principal="owner", role="user", tenant="red"
    )[0]
    assert observation.body == {"id": 7}
    assert observation.tags == ("burp-xml",)


def test_burp_xml_rejects_malformed_document():
    with pytest.raises(TrafficFormatError, match="invalid Burp XML"):
        BurpXmlIngestor().ingest("<items>", principal="x", role="user")
