from barq_crs.variant import PatchSeed, PatchSeededVariantEngine


DIFF = """diff --git a/service.py b/service.py
--- a/service.py
+++ b/service.py
@@ -1,2 +1,4 @@
 def read_record(records, index):
+    if index < 0:
+        raise ValueError("invalid")
     return records[index]
"""


def test_patch_seed_extracts_guarded_index():
    seed = PatchSeed.from_unified_diff(DIFF)
    assert "index" in seed.guarded_names


def test_finds_sibling_missing_index_guard(tmp_path):
    (tmp_path / "service.py").write_text(
        "def safe(records, index):\n    if index < 0:\n        raise ValueError\n    return records[index]\n\n"
        "def sibling(records, index):\n    return records[index]\n"
    )
    findings = PatchSeededVariantEngine().analyze(DIFF, tmp_path)
    assert len(findings) == 1
    assert findings[0].target.endswith("::sibling")


def test_ignores_invalid_python(tmp_path):
    (tmp_path / "broken.py").write_text("def nope(:")
    assert PatchSeededVariantEngine().analyze(DIFF, tmp_path) == []


def test_finds_missing_security_call(tmp_path):
    diff = """@@ -1,2 +1,3 @@
 def profile(user_id):
+    if not authorize(user_id):
+        raise PermissionError
     return load_profile(user_id)
"""
    (tmp_path / "profiles.py").write_text(
        "def fixed(user_id):\n    if not authorize(user_id):\n        raise PermissionError\n    return load_profile(user_id)\n\n"
        "def sibling(user_id):\n    return load_profile(user_id)\n"
    )
    findings = PatchSeededVariantEngine().analyze(diff, tmp_path)
    assert any(item.target.endswith("::sibling") for item in findings)
