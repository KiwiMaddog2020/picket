from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from picket.checkpoints import (
    CheckpointData,
    load_checkpoints,
    normalized_alert_cursors,
    repo_checkpoint,
)

ALERT_KINDS = ("code_scanning", "dependabot", "secret_scanning")


@dataclass(frozen=True)
class RepoSnapshot:
    repo: str
    pushed_at: str | None = None
    head_sha: str | None = None
    alert_cursors: dict[str, str] = field(default_factory=dict)


def _alert_timestamp(alert: dict[str, Any]) -> str:
    instance = alert.get("most_recent_instance")
    if isinstance(instance, dict):
        instance_time = instance.get("analysis_key") or instance.get("ref")
    else:
        instance_time = None
    return str(alert.get("updated_at") or alert.get("created_at") or instance_time or "")


def _alert_identity(alert: dict[str, Any]) -> str:
    rule = alert.get("rule")
    rule_id = rule.get("id") if isinstance(rule, dict) else None
    vulnerability = alert.get("security_vulnerability")
    package = vulnerability.get("package", {}) if isinstance(vulnerability, dict) else {}
    package_name = package.get("name") if isinstance(package, dict) else None
    identity = (
        alert.get("number")
        or alert.get("id")
        or alert.get("html_url")
        or alert.get("secret_type")
        or rule_id
        or package_name
        or "unknown"
    )
    return str(identity)


def newest_alert_cursor(alerts: list[dict[str, Any]], kind: str) -> str:
    if not alerts:
        return ""

    def key(alert: dict[str, Any]) -> tuple[str, str]:
        return (_alert_timestamp(alert), _alert_identity(alert))

    newest = max(alerts, key=key)
    return f"{kind}:{_alert_timestamp(newest)}:{_alert_identity(newest)}"


def changed_repos(
    checkpoints: CheckpointData,
    snapshots: list[RepoSnapshot],
) -> list[dict[str, Any]]:
    changed: list[dict[str, Any]] = []
    for snapshot in snapshots:
        checkpoint = repo_checkpoint(checkpoints, snapshot.repo)
        previous_cursors = normalized_alert_cursors(checkpoint)
        reasons: list[str] = []

        if not checkpoint:
            reasons.append("new_repo")
        if snapshot.pushed_at and checkpoint.get("last_pushed_at") != snapshot.pushed_at:
            reasons.append("pushed_at")
        if snapshot.head_sha and checkpoint.get("last_sha") != snapshot.head_sha:
            reasons.append("head_sha")

        for kind, cursor in snapshot.alert_cursors.items():
            if previous_cursors.get(kind, "") != cursor:
                reasons.append(f"{kind}_alerts")

        if reasons:
            changed.append(
                {
                    "repo": snapshot.repo,
                    "reasons": sorted(set(reasons)),
                    "pushed_at": snapshot.pushed_at,
                    "head_sha": snapshot.head_sha,
                    "alert_cursors": dict(sorted(snapshot.alert_cursors.items())),
                }
            )
    return changed


class GhClient:
    def __init__(self, gh_bin: str = "gh") -> None:
        self.gh_bin = gh_bin

    def run_json(self, args: list[str]) -> Any:
        completed = subprocess.run(
            [self.gh_bin, *args],
            check=True,
            capture_output=True,
            text=True,
        )
        if not completed.stdout.strip():
            return None
        return json.loads(completed.stdout)

    def list_repos(self, owner: str) -> list[str]:
        data = self.run_json(
            [
                "repo",
                "list",
                owner,
                "--json",
                "nameWithOwner",
                "--limit",
                "200",
            ]
        )
        if not isinstance(data, list):
            return []
        repos = [item.get("nameWithOwner") for item in data if isinstance(item, dict)]
        return sorted(repo for repo in repos if repo)

    def repo_view(self, repo: str) -> dict[str, Any]:
        data = self.run_json(
            [
                "repo",
                "view",
                repo,
                "--json",
                "nameWithOwner,pushedAt,defaultBranchRef",
            ]
        )
        if not isinstance(data, dict):
            raise ValueError(f"gh returned non-object repo view for {repo}")
        return data

    def alerts(self, repo: str, kind: str) -> list[dict[str, Any]]:
        owner, name = repo.split("/", 1)
        paths = {
            "code_scanning": f"/repos/{owner}/{name}/code-scanning/alerts?state=open",
            "dependabot": f"/repos/{owner}/{name}/dependabot/alerts?state=open",
            "secret_scanning": f"/repos/{owner}/{name}/secret-scanning/alerts?state=open",
        }
        try:
            data = self.run_json(["api", paths[kind]])
        except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
            # An unreadable alert endpoint (missing security_events scope, the
            # feature being off, or a 404) must not crash the whole sweep. Treat
            # it as no alerts of this kind and keep going, but say so on stderr.
            print(
                f"picket: warning: {kind} alerts unavailable for {repo} "
                f"({type(exc).__name__}); treating as none",
                file=sys.stderr,
            )
            return []
        return data if isinstance(data, list) else []


def _head_sha_from_view(view: dict[str, Any]) -> str | None:
    default_branch = view.get("defaultBranchRef")
    if not isinstance(default_branch, dict):
        return None
    target = default_branch.get("target")
    if isinstance(target, dict):
        oid = target.get("oid")
        return str(oid) if oid else None
    return None


def snapshot_repo(client: GhClient, repo: str) -> RepoSnapshot:
    view = client.repo_view(repo)
    alert_cursors = {
        kind: newest_alert_cursor(client.alerts(repo, kind), kind) for kind in ALERT_KINDS
    }
    return RepoSnapshot(
        repo=str(view.get("nameWithOwner") or repo),
        pushed_at=str(view.get("pushedAt") or "") or None,
        head_sha=_head_sha_from_view(view),
        alert_cursors=alert_cursors,
    )


def read_repos_file(path: str | Path) -> list[str]:
    repo_path = Path(path)
    if not repo_path.exists():
        return []
    repos: list[str] = []
    for line in repo_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            repos.append(stripped)
    return repos


def collect_snapshots(client: GhClient, repos: list[str]) -> list[RepoSnapshot]:
    snapshots: list[RepoSnapshot] = []
    for repo in repos:
        try:
            snapshots.append(snapshot_repo(client, repo))
        except (subprocess.CalledProcessError, json.JSONDecodeError, ValueError) as exc:
            # One unreachable repo (renamed, deleted, permission) must not kill
            # the sweep across the other 44.
            print(
                f"picket: warning: skipping {repo} ({type(exc).__name__}: {exc})",
                file=sys.stderr,
            )
    return snapshots


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="List repos with new commits or security alerts.")
    parser.add_argument("--checkpoint", default="state/checkpoints.json")
    parser.add_argument("--repos-file", default="config/repos.txt")
    parser.add_argument("--owner", default=None)
    parser.add_argument("--repo", action="append", default=[])
    parser.add_argument("--format", choices=("json", "names"), default="json")
    parser.add_argument("--gh-bin", default="gh")
    parser.add_argument("--dry-run", action="store_true", default=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    checkpoints = load_checkpoints(args.checkpoint)
    client = GhClient(args.gh_bin)

    repos = list(args.repo) or read_repos_file(args.repos_file)
    if not repos:
        repos = client.list_repos(args.owner)

    snapshots = collect_snapshots(client, repos)
    changed = changed_repos(checkpoints, snapshots)
    if args.format == "names":
        for item in changed:
            print(item["repo"])
    else:
        json.dump(changed, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
