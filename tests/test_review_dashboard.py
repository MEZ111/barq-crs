import json
import re

from barq_crs.dashboard import html_dashboard


def test_dashboard_escapes_embedded_content():
    title = '</script><img src=x onerror=alert(1)>'
    output = html_dashboard([], title)
    assert title not in output
    match = re.search(r'<script id="barq-data" type="application/json">(.*?)</script>', output, re.S)
    assert json.loads(match.group(1))['campaign'] == title


def test_dashboard_preserves_javascript_string_escape():
    output = html_dashboard([], 'review')
    assert ".join('\\n')" in output
    assert ".join('\n')" not in output
