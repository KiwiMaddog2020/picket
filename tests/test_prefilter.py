from __future__ import annotations

import json
import subprocess
from pathlib import Path

from picket.prefilter import RepoSnapshot, changed_repos, newest_alert_cursor


def test_changed_repos_lists_only_real_deltas() -> None:
    checkpoints = {
        "repos": {
            "octocat/quiet": {
                "last_sha": "aaa",
                "last_pushed_at": "2026-06-01T00:00:00Z",
                "last_alert_cursor": {
                    "code_scanning": "",
                    "dependabot": "dependabot:2026-06-01T00:00:00Z:3",
                    "secret_scanning": "",
                },
            },
            "octocat/noisy": {
                "last_sha": "old",
                "last_pushed_at": "2026-06-01T00:00:00Z",
                "last_alert_cursor": {
                    "code_scanning": "",
                    "dependabot": "",
                    "secret_scanning": "",
                },
            },
        }
    }
    snapshots = [
        RepoSnapshot(
            repo="octocat/quiet",
            pushed_at="2026-06-01T00:00:00Z",
            head_sha="aaa",
            alert_cursors={
                "code_scanning": "",
                "dependabot": "dependabot:2026-06-01T00:00:00Z:3",
                "secret_scanning": "",
            },
        ),
        RepoSnapshot(
            repo="octocat/noisy",
            pushed_at="2026-06-02T00:00:00Z",
            head_sha="new",
            alert_cursors={
                "code_scanning": "code_scanning:2026-06-02T00:00:00Z:9",
                "dependabot": "",
                "secret_scanning": "",
            },
        ),
    ]

    changed = changed_repos(checkpoints, snapshots)

    assert [item["repo"] for item in changed] == ["octocat/noisy"]
    assert changed[0]["reasons"] == ["code_scanning_alerts", "head_sha", "pushed_at"]


def test_no_delta_prefilter_returns_empty_before_any_model_context() -> None:
    checkpoints = {
        "repos": {
            "octocat/quiet": {
                "last_sha": "aaa",
                "last_pushed_at": "2026-06-01T00:00:00Z",
                "last_alert_cursor": {"code_scanning": "", "dependabot": ""},
            }
        }
    }
    snapshots = [
        RepoSnapshot(
            repo="octocat/quiet",
            pushed_at="2026-06-01T00:00:00Z",
            head_sha="aaa",
            alert_cursors={"code_scanning": "", "dependabot": ""},
        )
    ]

    assert changed_repos(checkpoints, snapshots) == []


def test_newest_alert_cursor_is_stable() -> None:
    alerts = [
        {"number": 1, "updated_at": "2026-06-01T00:00:00Z"},
        {"number": 2, "updated_at": "2026-06-03T00:00:00Z"},
        {"number": 3, "updated_at": "2026-06-02T00:00:00Z"},
    ]

    assert newest_alert_cursor(alerts, "dependabot") == "dependabot:2026-06-03T00:00:00Z:2"


def test_changed_repos_shell_uses_fake_gh_without_network(tmp_path: Path) -> None:
    checkpoint = tmp_path / "checkpoints.json"
    checkpoint.write_text(
        json.dumps(
            {
                "repos": {
                    "octocat/quiet": {
                        "last_sha": "same",
                        "last_pushed_at": "2026-06-01T00:00:00Z",
                        "last_alert_cursor": {
                            "code_scanning": "",
                            "dependabot": "",
                            "secret_scanning": "",
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    fake_gh = tmp_path / "gh"
    repo_view_json = json.dumps(
        {
            "nameWithOwner": "octocat/quiet",
            "pushedAt": "2026-06-01T00:00:00Z",
            "defaultBranchRef": {"target": {"oid": "same"}},
        }
    )
    fake_gh.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == "repo view" ]]; then
  printf '%s\\n' '{repo_view_json}'
elif [[ "$1" == "api" ]]; then
  printf '[]\\n'
else
  printf 'unexpected gh args: %s\\n' "$*" >&2
  exit 2
fi
""",
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)

    completed = subprocess.run(
        [
            "bin/changed_repos.sh",
            "--checkpoint",
            str(checkpoint),
            "--repo",
            "octocat/quiet",
        ],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": f"{tmp_path}:/usr/bin:/bin", "GH_BIN": str(fake_gh)},
    )

    assert json.loads(completed.stdout) == []


def test_alerts_unavailable_returns_empty_instead_of_crashing() -> None:
    from picket.prefilter import GhClient

    class FailingGh(GhClient):
        def run_json(self, args: list[str]) -> object:
            raise subprocess.CalledProcessError(1, args)

    client = FailingGh()
    assert client.alerts("octocat/example", "code_scanning") == []


def test_collect_snapshots_skips_unreachable_repo() -> None:
    from picket.prefilter import GhClient, collect_snapshots

    class PartialGh(GhClient):
        def repo_view(self, repo: str) -> dict[str, object]:
            if repo.endswith("/bad"):
                raise subprocess.CalledProcessError(1, ["repo", "view", repo])
            return {
                "nameWithOwner": repo,
                "pushedAt": "2026-06-01T00:00:00Z",
                "defaultBranchRef": {"target": {"oid": "abc"}},
            }

        def alerts(self, repo: str, kind: str) -> list[dict[str, object]]:
            return []

    snapshots = collect_snapshots(PartialGh(), ["octocat/good", "octocat/bad"])
    assert [snapshot.repo for snapshot in snapshots] == ["octocat/good"]
