from __future__ import annotations

from picket import audit_inputs as ai

# (path, blob_sha) entries standing in for a git-tree.
BASE = [
    ("package-lock.json", "deplock1"),
    ("src/app.ts", "src1"),
    ("src/util.py", "util1"),
    (".github/workflows/ci.yml", "wf1"),
    ("README.md", "readme1"),
    (".env.example", "envex1"),
]


def test_predicates_classify() -> None:
    assert ai._is_dep("package-lock.json")
    assert ai._is_dep("a/b/requirements.txt")
    assert not ai._is_dep("README.md")
    assert ai._is_sast("src/app.ts")
    assert ai._is_sast("x.py")
    assert not ai._is_sast("README.md")
    assert ai._is_config(".github/workflows/ci.yml")
    assert ai._is_config(".env.example")
    assert ai._is_config("prod.env")
    assert not ai._is_config("README.md")


def test_dep_change_moves_only_deps_hash() -> None:
    before = ai.dimension_hashes(BASE, "sha0")
    changed = [(p, "deplock2" if p == "package-lock.json" else s) for p, s in BASE]
    after = ai.dimension_hashes(changed, "sha0")
    assert after["deps"] != before["deps"]
    assert after["sast"] == before["sast"]
    assert after["config"] == before["config"]


def test_source_change_moves_only_sast_hash() -> None:
    before = ai.dimension_hashes(BASE, "sha0")
    changed = [(p, "src2" if p == "src/app.ts" else s) for p, s in BASE]
    after = ai.dimension_hashes(changed, "sha0")
    assert after["sast"] != before["sast"]
    assert after["deps"] == before["deps"]
    assert after["config"] == before["config"]


def test_workflow_change_moves_only_config_hash() -> None:
    before = ai.dimension_hashes(BASE, "sha0")
    changed = [(p, "wf2" if p.endswith("ci.yml") else s) for p, s in BASE]
    after = ai.dimension_hashes(changed, "sha0")
    assert after["config"] != before["config"]
    assert after["deps"] == before["deps"]
    assert after["sast"] == before["sast"]


def test_secret_hash_keys_on_head() -> None:
    a = ai.dimension_hashes(BASE, "sha0")
    b = ai.dimension_hashes(BASE, "sha1")
    assert a["secret"] != b["secret"]  # any new commit re-scans history
    assert a["deps"] == b["deps"]  # but tree-based dims are HEAD-independent


def test_docs_only_change_moves_nothing_expensive() -> None:
    before = ai.dimension_hashes(BASE, "sha0")
    changed = [(p, "readme2" if p == "README.md" else s) for p, s in BASE]
    after = ai.dimension_hashes(changed, "sha0")
    assert after["deps"] == before["deps"]
    assert after["sast"] == before["sast"]
    assert after["config"] == before["config"]


def test_hash_pairs_order_independent_and_stable() -> None:
    assert ai._hash_pairs([("a", "1"), ("b", "2")]) == ai._hash_pairs([("b", "2"), ("a", "1")])
    assert ai._hash_pairs([("a", "1")]) != ai._hash_pairs([("a", "2")])
