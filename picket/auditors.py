"""The four deep-audit dimensions. Each returns findings in the sec_scan shape.

Unlike the hourly delta scan, these run repo-WIDE when a dimension is due:
- deps:   open Dependabot alerts across the whole repo.
- secret: GitHub secret-scanning alerts (history-covering) + an enablement nudge,
          and an optional full-tree regex sweep (deep=True) where scanning is off.
- sast:   GitHub code-scanning alerts + an enablement nudge, and an optional
          full-tree dangerous-pattern sweep (deep=True).
- config: posture checks via the GitHub API + tree (workflow token scopes, missing
          scanning, committed .env files, unprotected default branch).

semgrep/gitleaks are intentionally NOT required: GitHub's native scanners plus the
deterministic patterns in sec_scan are the levers. Every check is best-effort, so
one unreadable endpoint never aborts the dimension.
"""

from __future__ import annotations

import base64
import binascii
import json
import subprocess
from typing import Any

from picket.prefilter import GhClient
from picket.sec_scan import DANGEROUS_LINE, SECRET_LINE, findings_from_alert_payloads

# File extensions worth a deep content sweep when a native scanner is off.
SWEEPABLE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".sh", ".rb", ".env"}
MAX_DEEP_FILES = 400  # cap the deep sweep so a giant repo cannot blow the budget


def _gh_safe(client: GhClient, path: str) -> Any | None:
    """A GitHub API GET that returns None instead of raising on any failure."""
    try:
        return client.run_json(["api", path])
    except (subprocess.CalledProcessError, json.JSONDecodeError, ValueError):
        return None


# --- deps -----------------------------------------------------------------

def audit_deps(repo: str, *, client: GhClient) -> list[dict[str, Any]]:
    """Every open Dependabot alert, repo-wide, as findings."""
    alerts = client.alerts(repo, "dependabot")
    return findings_from_alert_payloads(repo, {"dependabot": alerts})


# --- secret ---------------------------------------------------------------

def _scanning_status(client: GhClient, repo: str, feature: str) -> str | None:
    """security_and_analysis.<feature>.status, or None if unreadable (no admin)."""
    data = _gh_safe(client, f"/repos/{repo}")
    analysis = data.get("security_and_analysis") if isinstance(data, dict) else None
    entry = analysis.get(feature) if isinstance(analysis, dict) else None
    return entry.get("status") if isinstance(entry, dict) else None


def audit_secret(
    repo: str,
    *,
    client: GhClient,
    entries: list[tuple[str, str]] | None = None,
    deep: bool = False,
) -> list[dict[str, Any]]:
    alerts = client.alerts(repo, "secret_scanning")
    findings = findings_from_alert_payloads(repo, {"secret_scanning": alerts})
    if _scanning_status(client, repo, "secret_scanning") == "disabled":
        findings.append(
            {
                "repo": repo,
                "source": "audit",
                "kind": "config",
                "low_risk_config": True,
                "setting": "secret_scanning",
                "title": "Secret scanning is disabled (full-history coverage is off)",
                "evidence": "security_and_analysis.secret_scanning.status == disabled",
            }
        )
        if deep and entries is not None:
            findings.extend(_content_sweep(client, repo, entries, SECRET_LINE, "secret"))
    return findings


# --- sast ------------------------------------------------------------------

def audit_sast(
    repo: str,
    *,
    client: GhClient,
    entries: list[tuple[str, str]] | None = None,
    deep: bool = False,
) -> list[dict[str, Any]]:
    alerts = client.alerts(repo, "code_scanning")
    findings = findings_from_alert_payloads(repo, {"code_scanning": alerts})
    if not alerts and deep and entries is not None:
        findings.extend(_content_sweep(client, repo, entries, DANGEROUS_LINE, "code_scanning"))
    return findings


# --- config + perms --------------------------------------------------------

def audit_config(
    repo: str,
    *,
    client: GhClient,
    entries: list[tuple[str, str]] | None = None,
    default_branch: str = "main",
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    # 1. Workflow token defaults to read/write -> recommend least privilege.
    perms = _gh_safe(client, f"/repos/{repo}/actions/permissions/workflow")
    if isinstance(perms, dict) and perms.get("default_workflow_permissions") == "write":
        findings.append(
            {
                "repo": repo,
                "source": "audit",
                "kind": "config",
                "low_risk_config": True,
                "setting": "workflow_permissions",
                "file": ".github/workflows",
                "title": "GITHUB_TOKEN defaults to write across all workflows",
                "evidence": "actions/permissions/workflow.default_workflow_permissions == write",
            }
        )

    # 2. A committed .env (not an example) is a live secret-exposure risk.
    for path, _sha in entries or []:
        low = path.lower()
        name = low.rsplit("/", 1)[-1]
        if (name == ".env" or low.endswith("/.env") or low.endswith(".env.local")) and (
            "example" not in low and "sample" not in low
        ):
            findings.append(
                {
                    "repo": repo,
                    "source": "audit",
                    "kind": "secret",
                    "secret": True,
                    "file": path,
                    "title": f"Committed environment file in the repo: {path}",
                    "evidence": "a .env file is tracked in git; likely contains live secrets",
                }
            )

    # 3. Default branch has no protection.
    protection = _gh_safe(client, f"/repos/{repo}/branches/{default_branch}/protection")
    if protection is None:
        findings.append(
            {
                "repo": repo,
                "source": "audit",
                "kind": "config",
                "low_risk_config": True,
                "setting": "branch_protection",
                "title": f"Default branch '{default_branch}' has no branch protection",
                "evidence": "branches/{branch}/protection returned no ruleset",
            }
        )
    return findings


# --- deep content sweep (gated; native scanners are preferred) -------------

def _blob_text(client: GhClient, repo: str, blob_sha: str) -> str:
    data = _gh_safe(client, f"/repos/{repo}/git/blobs/{blob_sha}")
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        return ""
    try:
        return base64.b64decode(data.get("content", "")).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return ""


def _content_sweep(
    client: GhClient,
    repo: str,
    entries: list[tuple[str, str]],
    pattern: Any,
    kind: str,
) -> list[dict[str, Any]]:
    """Regex-scan the content of sweepable files. Only used when a scanner is off."""
    findings: list[dict[str, Any]] = []
    scanned = 0
    for path, blob_sha in entries:
        if scanned >= MAX_DEEP_FILES:
            break
        if "." + path.rsplit(".", 1)[-1].lower() not in SWEEPABLE_EXTENSIONS:
            continue
        scanned += 1
        for number, line in enumerate(_blob_text(client, repo, blob_sha).splitlines(), start=1):
            if pattern.search(line):
                findings.append(
                    {
                        "repo": repo,
                        "source": "audit",
                        "kind": kind,
                        "secret": kind == "secret",
                        "file": path,
                        "line": number,
                        "title": f"Pattern match in tree sweep ({kind})",
                        "evidence": line.strip()[:200],
                    }
                )
                break  # one hit per file is enough to flag it
    return findings


DIMENSION_AUDITORS = {
    "deps": audit_deps,
    "secret": audit_secret,
    "sast": audit_sast,
    "config": audit_config,
}


def audit_repo(
    repo: str,
    due_dimensions: list[str],
    *,
    client: GhClient,
    entries: list[tuple[str, str]] | None = None,
    default_branch: str = "main",
    deep: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    """Run each due dimension for a repo, returning {dimension: findings}."""
    results: dict[str, list[dict[str, Any]]] = {}
    for dimension in due_dimensions:
        if dimension == "deps":
            results[dimension] = audit_deps(repo, client=client)
        elif dimension == "secret":
            results[dimension] = audit_secret(repo, client=client, entries=entries, deep=deep)
        elif dimension == "sast":
            results[dimension] = audit_sast(repo, client=client, entries=entries, deep=deep)
        elif dimension == "config":
            results[dimension] = audit_config(
                repo, client=client, entries=entries, default_branch=default_branch
            )
    return results
