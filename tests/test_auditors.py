from __future__ import annotations

import subprocess
from typing import Any

from picket import auditors

REPO = "o/r"


class FakeClient:
    """Stand-in GhClient: canned alerts per kind and canned API responses per path."""

    def __init__(
        self,
        *,
        alerts: dict[str, list[dict[str, Any]]] | None = None,
        api: dict[str, Any] | None = None,
        forbidden: tuple[str, ...] = (),
    ) -> None:
        self._alerts = alerts or {}
        self._api = api or {}
        self._forbidden = forbidden

    def alerts(self, repo: str, kind: str) -> list[dict[str, Any]]:
        return self._alerts.get(kind, [])

    def run_json(self, args: list[str]) -> Any:
        path = args[1]
        if path in self._api:
            return self._api[path]
        # un-stubbed paths fail like gh: a 403 for forbidden prefixes, else a 404.
        forbidden = any(path.startswith(prefix) for prefix in self._forbidden)
        stderr = "gh: HTTP 403 not accessible" if forbidden else "gh: HTTP 404 Not Found"
        raise subprocess.CalledProcessError(1, args, stderr=stderr)


def _dependabot_alert() -> dict[str, Any]:
    return {
        "number": 1,
        "html_url": "https://github.com/o/r/security/dependabot/1",
        "security_vulnerability": {
            "package": {"name": "vite"},
            "first_patched_version": {"identifier": "8.1.0"},
            "severity": "high",
        },
        "security_advisory": {"summary": "vite vuln"},
        "update_type": "patch",
    }


def test_audit_deps_surfaces_open_alerts() -> None:
    client = FakeClient(alerts={"dependabot": [_dependabot_alert()]})
    findings = auditors.audit_deps(REPO, client=client)
    assert len(findings) == 1
    assert findings[0]["package"] == "vite"
    assert findings[0]["patched_version"] == "8.1.0"


def test_audit_secret_reports_alerts_and_disabled_scanning() -> None:
    client = FakeClient(
        alerts={"secret_scanning": [{"secret_type_display_name": "AWS key", "html_url": "u"}]},
        api={"/repos/o/r": {"security_and_analysis": {"secret_scanning": {"status": "disabled"}}}},
    )
    findings = auditors.audit_secret(REPO, client=client)
    kinds = {f["kind"] for f in findings}
    assert "secret_scanning" in kinds  # the live alert
    assert any(f.get("setting") == "secret_scanning" for f in findings)  # the disabled nudge


def test_audit_secret_no_nudge_when_enabled() -> None:
    client = FakeClient(
        api={"/repos/o/r": {"security_and_analysis": {"secret_scanning": {"status": "enabled"}}}}
    )
    findings = auditors.audit_secret(REPO, client=client)
    assert not any(f.get("setting") == "secret_scanning" for f in findings)


def test_audit_sast_surfaces_code_scanning_alerts() -> None:
    client = FakeClient(
        alerts={"code_scanning": [{"rule": {"description": "SQL injection", "severity": "high"}}]}
    )
    findings = auditors.audit_sast(REPO, client=client)
    assert findings and findings[0]["kind"] == "code_scanning"


def test_audit_config_flags_write_token_committed_env_and_no_protection() -> None:
    client = FakeClient(
        api={
            "/repos/o/r/actions/permissions/workflow": {"default_workflow_permissions": "write"},
            # branch protection path intentionally absent -> reads as unprotected
        }
    )
    entries = [("apps/api/.env", "blob1"), (".env.example", "blob2"), ("src/x.py", "blob3")]
    findings = auditors.audit_config(REPO, client=client, entries=entries, default_branch="main")
    settings = {f.get("setting") for f in findings}
    assert "workflow_permissions" in settings
    assert "branch_protection" in settings
    committed_env = [f for f in findings if f.get("secret") and f["file"] == "apps/api/.env"]
    assert len(committed_env) == 1  # the real .env, not the .env.example


def test_audit_config_does_not_flag_protection_it_cannot_read() -> None:
    # a 403 (no admin to read protection, e.g. the App token) must NOT read as "missing"
    client = FakeClient(
        api={"/repos/o/r/actions/permissions/workflow": {"default_workflow_permissions": "read"}},
        forbidden=("/repos/o/r/branches/",),
    )
    findings = auditors.audit_config(REPO, client=client, entries=[("README.md", "b")])
    assert not any(f.get("setting") == "branch_protection" for f in findings)


def test_audit_config_quiet_when_hardened() -> None:
    client = FakeClient(
        api={
            "/repos/o/r/actions/permissions/workflow": {"default_workflow_permissions": "read"},
            "/repos/o/r/branches/main/protection": {"required_pull_request_reviews": {}},
        }
    )
    findings = auditors.audit_config(REPO, client=client, entries=[("README.md", "b")])
    assert findings == []


def test_audit_repo_dispatches_only_due_dimensions() -> None:
    client = FakeClient(alerts={"dependabot": [_dependabot_alert()]})
    results = auditors.audit_repo(REPO, ["deps"], client=client, entries=[])
    assert set(results) == {"deps"}
    assert len(results["deps"]) == 1


def test_deep_content_sweep_finds_secret_when_scanning_off() -> None:
    import base64

    leak = "api_key = 'AKIAREALLYLONGSECRETVALUE'"
    client = FakeClient(
        api={
            "/repos/o/r": {"security_and_analysis": {"secret_scanning": {"status": "disabled"}}},
            "/repos/o/r/git/blobs/blob1": {
                "encoding": "base64",
                "content": base64.b64encode(leak.encode()).decode(),
            },
        }
    )
    findings = auditors.audit_secret(
        REPO, client=client, entries=[("config.py", "blob1")], deep=True
    )
    swept = [f for f in findings if f["source"] == "audit" and f.get("line")]
    assert swept and swept[0]["file"] == "config.py"
