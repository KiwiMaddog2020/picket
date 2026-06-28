from __future__ import annotations

import subprocess
from typing import Any

from picket import audit_sprint as asp
from picket.audit_ledger import load_ledger


class FakeEscalator:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def escalate_summary(self, body: str, summary: str) -> dict[str, Any]:
        self.sent.append((body, summary))
        return {"action": "would_escalate"}


class FakeClient:
    def __init__(self, *, alerts: dict[str, list] | None = None, api: dict[str, Any] | None = None):
        self._alerts = alerts or {}
        self._api = api or {}

    def alerts(self, repo: str, kind: str) -> list[dict[str, Any]]:
        return self._alerts.get(kind, [])

    def run_json(self, args: list[str]) -> Any:
        path = args[1]
        if path in self._api:  # exact match first (so /repos/o/r doesn't swallow sub-paths)
            return self._api[path]
        for key in sorted(self._api, key=len, reverse=True):
            if key.endswith("/") and path.startswith(key):  # only explicit prefix keys
                return self._api[key]
        raise subprocess.CalledProcessError(1, args)


def _client() -> FakeClient:
    return FakeClient(
        alerts={
            "dependabot": [
                {
                    "number": 1,
                    "html_url": "u",
                    "security_vulnerability": {
                        "package": {"name": "vite"},
                        "first_patched_version": {"identifier": "8.1.0"},
                        "severity": "high",
                    },
                    "security_advisory": {"summary": "vite vuln"},
                    "update_type": "patch",
                }
            ]
        },
        api={
            "/repos/o/r/git/trees/": {
                "tree": [
                    {"type": "blob", "path": "package-lock.json", "sha": "b1"},
                    {"type": "blob", "path": "src/x.py", "sha": "b2"},
                ]
            },
            "/repos/o/r/actions/permissions/workflow": {"default_workflow_permissions": "write"},
            "/repos/o/r/commits/main": {"sha": "deadbeef"},
            "/repos/o/r": {"default_branch": "main", "visibility": "private", "private": True},
        },
    )


def test_full_sprint_in_shadow(tmp_path) -> None:
    allowlist = tmp_path / "allow.txt"
    allowlist.write_text("o/r\n", encoding="utf-8")
    ledger_path = tmp_path / "ledger.json"
    escalator = FakeEscalator()

    result = asp.run_sprint(
        client=_client(),
        runner=object(),
        escalator=escalator,
        allowlist_path=allowlist,
        ledger_path=ledger_path,
        day_of_month=3,  # first Sunday -> sprint 1
        shadow=True,
        drafter=lambda *a, **k: None,  # never reached here; guards against a real claude call
        self_checker=lambda *a, **k: True,
    )

    assert result["sprint_index"] == 1
    assert result["audited"] == ["o/r"]
    assert result["counts"]["deferred"] == 1  # the dependabot alert defers to the auto-merge layer
    assert result["counts"]["escalations"] == 2  # workflow-perms + no branch protection

    # ledger persisted with all four dimensions recorded for the repo
    ledger = load_ledger(ledger_path)
    dims = ledger["repos"]["o/r"]["dimensions"]
    assert set(dims) == {"deps", "secret", "sast", "config"}
    assert dims["deps"]["clean_streak"] == 0  # the open alert is a finding -> streak reset

    # one digest went out, naming the sprint
    assert len(escalator.sent) == 1
    body, summary = escalator.sent[0]
    assert "Audit sprint 1/4" in body
    assert "shadow" in body.lower()
    assert "sprint 1/4" in summary


def test_render_digest_clean_when_no_findings() -> None:
    empty = {"proposed": [], "escalations": [], "deferred": [], "rotations": []}
    out = asp.render_audit_digest(empty, sprint_index=2, repos_audited=["a", "b"], shadow=False)
    assert "✅ clean" in out
    assert "shadow" not in out.lower()


def test_second_run_skips_unchanged_repo(tmp_path) -> None:
    """After a clean dimension reaches baseline, an unchanged input is not re-audited."""
    allowlist = tmp_path / "allow.txt"
    allowlist.write_text("o/r\n", encoding="utf-8")
    ledger_path = tmp_path / "ledger.json"
    # a client with NO findings anywhere, hardened config
    clean_client = FakeClient(
        api={
            "/repos/o/r/git/trees/": {"tree": [{"type": "blob", "path": "README.md", "sha": "r1"}]},
            "/repos/o/r/actions/permissions/workflow": {"default_workflow_permissions": "read"},
            "/repos/o/r/branches/main/protection": {"required_pull_request_reviews": {}},
            "/repos/o/r/commits/main": {"sha": "sha1"},
            "/repos/o/r": {"default_branch": "main", "visibility": "private", "private": True},
        }
    )
    common = dict(
        client=clean_client,
        runner=object(),
        allowlist_path=allowlist,
        ledger_path=ledger_path,
        shadow=True,
    )
    # two baseline passes establish the 2-clean baseline on unchanged inputs
    asp.run_sprint(escalator=FakeEscalator(), day_of_month=3, **common)
    asp.run_sprint(escalator=FakeEscalator(), day_of_month=10, **common)
    # third pass: nothing changed, baseline met, not stale -> nothing is due
    third = asp.run_sprint(escalator=FakeEscalator(), day_of_month=17, **common)
    assert third["due_total"] == 0
    assert third["audited"] == []
