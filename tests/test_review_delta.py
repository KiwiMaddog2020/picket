from __future__ import annotations

from picket.review import review_delta


def test_review_delta_filters_patch_before_any_model_context() -> None:
    delta = {
        "repo": "octocat/example",
        "base_sha": "old",
        "head_sha": "new",
        "patch": """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,1 +1,2 @@
 print("ok")
+AWS_SECRET_ACCESS_KEY = "not-a-real-but-shaped-secret"
""",
        "alerts": {},
    }

    result = review_delta(delta)

    assert result["dry_run"] is True
    assert result["findings"][0]["tier"] == "tier-3"
    assert result["findings"][0]["repo_write_allowed"] is False
    assert "do not write" in result["proposal"]


def test_review_delta_classifies_patch_dependency_bump_tier_1() -> None:
    delta = {
        "repo": "octocat/example",
        "base_sha": "old",
        "head_sha": "new",
        "patch": """diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1 +1 @@
-django==4.2.1
+django==4.2.2
""",
        "alerts": {},
    }

    result = review_delta(delta)

    assert result["findings"][0]["tier"] == "tier-1"
    assert result["findings"][0]["auto_merge_candidate"] is True
    assert "green CI" in result["proposal"]

