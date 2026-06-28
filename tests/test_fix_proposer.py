from __future__ import annotations

import base64
from typing import Any

from picket import fix_proposer as fp

VALID_DIFF = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-secret='abc'\n+secret=os.environ['S']\n"


class FakeClient:
    def run_json(self, args: list[str]) -> Any:
        path = args[1]
        if "/contents/" in path:
            return {"encoding": "base64", "content": base64.b64encode(b"x = 1\n").decode()}
        raise ValueError(f"no stub for {path}")


def _f(**kw: Any) -> dict[str, Any]:
    base = {"repo": "o/r"}
    base.update(kw)
    return base


def test_plan_routes_dependency_to_defer() -> None:
    plan = fp.plan_fix(_f(kind="dependabot", source="dependabot", update_type="patch"))
    assert plan["action"] == fp.DEFER


def test_plan_routes_setting_to_escalate() -> None:
    plan = fp.plan_fix(_f(kind="config", setting="secret_scanning", title="scanning off"))
    assert plan["action"] == fp.ESCALATE


def test_plan_secret_with_file_drafts_and_requires_rotation() -> None:
    plan = fp.plan_fix(_f(kind="secret", secret=True, file="config.py", title="committed env"))
    assert plan["action"] == fp.DRAFT_PR
    assert plan["requires_rotation"] is True


def test_plan_secret_without_file_escalates_but_still_rotates() -> None:
    plan = fp.plan_fix(_f(kind="secret_scanning", secret=True, title="AWS key"))
    assert plan["action"] == fp.ESCALATE
    assert plan["requires_rotation"] is True


def test_secret_scanning_nudge_is_not_a_rotation() -> None:
    # a config setting whose title merely says "secret" must NOT cry rotate-a-credential
    plan = fp.plan_fix(
        _f(kind="config", setting="secret_scanning", title="Secret scanning is disabled")
    )
    assert plan["action"] == fp.ESCALATE
    assert plan["requires_rotation"] is False


def test_plan_code_scanning_with_file_drafts() -> None:
    plan = fp.plan_fix(_f(kind="code_scanning", file="src/x.py", title="SQL injection"))
    assert plan["action"] == fp.DRAFT_PR
    assert plan["tier"] == "tier-2"


def test_plan_auth_change_drafts_for_review() -> None:
    plan = fp.plan_fix(_f(kind="code_scanning", file="src/auth/login.ts", title="auth bypass"))
    assert plan["action"] == fp.DRAFT_PR
    assert plan["tier"] == "tier-3"  # auth-touching, escalation-grade but drafted for approval


def test_looks_like_diff() -> None:
    assert fp.looks_like_diff(VALID_DIFF)
    assert not fp.looks_like_diff("just some prose")
    assert not fp.looks_like_diff("")


def test_build_draft_prompt_includes_file() -> None:
    prompt = fp.build_draft_prompt(_f(file="config.py", title="x"), "content")
    assert "config.py" in prompt
    assert "unified diff" in prompt


def test_propose_fixes_shadow_plans_without_executing() -> None:
    calls: list[Any] = []
    findings = [
        _f(kind="code_scanning", file="src/x.py", title="SQLi"),
        _f(kind="dependabot", source="dependabot", update_type="patch", title="bump"),
        _f(kind="config", setting="secret_scanning", title="scanning off"),
        _f(kind="secret", secret=True, file="config.py", title="committed env"),
        _f(kind="secret_scanning", secret=True, title="AWS key"),
    ]
    report = fp.propose_fixes(
        findings,
        client=FakeClient(),
        drafter=lambda f, c, **k: VALID_DIFF,
        self_checker=lambda f, p, **k: True,
        executor=lambda *a, **k: calls.append(a) or {"action": "created_pr"},
        shadow=True,
    )
    assert len(report["proposed"]) == 2  # code_scanning + secret strip
    assert len(report["deferred"]) == 1  # the dependabot alert
    assert len(report["escalations"]) == 2  # the setting + the file-less secret
    assert len(report["rotations"]) == 2  # both secret findings
    assert calls == []  # shadow: executor never runs
    assert all("patch" in p for p in report["proposed"])


def test_propose_fixes_live_invokes_executor() -> None:
    calls: list[Any] = []
    report = fp.propose_fixes(
        [_f(kind="code_scanning", file="src/x.py", title="SQLi")],
        client=FakeClient(),
        drafter=lambda f, c, **k: VALID_DIFF,
        self_checker=lambda f, p, **k: True,
        executor=lambda *a, **k: calls.append(k) or {"action": "created_pr"},
        shadow=False,
    )
    assert len(calls) == 1  # live: executor runs for the drafted PR
    assert report["proposed"][0]["result"]["action"] == "created_pr"


def test_propose_fixes_failed_draft_falls_back_to_escalation() -> None:
    report = fp.propose_fixes(
        [_f(kind="code_scanning", file="src/x.py", title="SQLi")],
        client=FakeClient(),
        drafter=lambda f, c, **k: None,  # drafter declines
        self_checker=lambda f, p, **k: True,
        shadow=True,
    )
    assert report["proposed"] == []
    assert len(report["escalations"]) == 1
