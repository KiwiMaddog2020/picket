"""Auto-merge trusted-author PRs that are safe.

Lists open PRs and, for the ones whose author is in the trusted set, enables
GitHub auto-merge only when every safety condition holds:

* the author is trusted (set ``PICKET_TRUSTED_PR_AUTHORS``; defaults to
  ``dependabot[bot]`` only -- add your own GitHub login to trust your own PRs),
* it is not a draft,
* it is a same-repo branch, not a fork (a fork can't be trusted by author),
* the diff touches no tier-3 (secret / auth / payment) path,
* no required check is failing,
* there is no merge conflict.

Auto-merge is enabled with ``gh pr merge --auto``, so GitHub still does the
final wait-for-green before the PR actually lands. Dry-run by default, and it
honours the same live allowlist as the rest of Picket, so nothing merges until
a repo is explicitly opted in.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from picket.apply import (
    Runner,
    SubprocessRunner,
    live_repo_enabled,
    load_allowlist,
)
from picket.tiers import is_secret_finding, touches_auth_or_payment

DEFAULT_TRUSTED_AUTHORS = ("dependabot[bot]",)

# GitHub's computed merge state. Only these mean "mergeable now, nothing
# failing"; any other value is a reason to wait. Using mergeStateStatus (one
# enum) instead of statusCheckRollup avoids the deep checkSuite.workflowRun
# expansion, which would require an Actions:Read grant the bot omits.
MERGEABLE_STATES = {"CLEAN", "HAS_HOOKS"}
MERGE_STATE_REASON = {
    "DIRTY": "merge_conflict",
    "BEHIND": "behind_base",
    "UNSTABLE": "checks_not_green",
    "BLOCKED": "blocked",
    "DRAFT": "draft",
    "UNKNOWN": "state_pending",
}


def trusted_authors(override: str | None = None) -> set[str]:
    raw = override if override is not None else os.environ.get("PICKET_TRUSTED_PR_AUTHORS", "")
    parsed = {item.strip() for item in raw.split(",") if item.strip()}
    return parsed or set(DEFAULT_TRUSTED_AUTHORS)


def file_is_sensitive(path: str) -> bool:
    """A changed file is tier-3 if it reads as a secret or auth/payment path."""
    finding = {"file": path}
    return is_secret_finding(finding) or touches_auth_or_payment(finding) is not None


def normalize_author(login: str) -> str:
    """Canonicalise bot logins to the ``name[bot]`` form.

    ``gh pr list`` reports bot authors as ``app/dependabot``, while ``gh search``
    and the web UI use ``dependabot[bot]``. Normalise so a single trusted-author
    entry matches regardless of which API surfaced the PR.
    """
    if login.startswith("app/"):
        return f"{login[len('app/'):]}[bot]"
    return login


@dataclass(frozen=True)
class PullRequest:
    repo: str
    number: int
    author: str
    is_draft: bool
    is_fork: bool
    merge_state: str
    files: tuple[str, ...] = ()


def evaluate_pr(pr: PullRequest, *, trusted: set[str]) -> dict[str, Any]:
    """Pure decision: should this PR auto-merge, and if not, exactly why not."""
    reasons: list[str] = []
    if pr.author not in trusted:
        reasons.append("untrusted_author")
    if pr.is_draft:
        reasons.append("draft")
    if pr.is_fork:
        reasons.append("fork")
    if pr.merge_state not in MERGEABLE_STATES:
        reasons.append(
            MERGE_STATE_REASON.get(pr.merge_state, f"merge_state_{pr.merge_state.lower()}")
        )
    sensitive = sorted(path for path in pr.files if file_is_sensitive(path))
    if sensitive:
        reasons.append("tier3_paths")
    reasons = list(dict.fromkeys(reasons))
    return {
        "repo": pr.repo,
        "number": pr.number,
        "author": pr.author,
        "decision": "auto_merge" if not reasons else "skip",
        "reasons": reasons,
        "sensitive_files": sensitive,
    }


def parse_pull_requests(repo: str, payload: list[dict[str, Any]]) -> list[PullRequest]:
    owner = repo.split("/", 1)[0]
    pulls: list[PullRequest] = []
    for item in payload:
        author = normalize_author(str((item.get("author") or {}).get("login", "")))
        head_owner = str((item.get("headRepositoryOwner") or {}).get("login", owner))
        files = tuple(str(entry.get("path", "")) for entry in (item.get("files") or []))
        pulls.append(
            PullRequest(
                repo=repo,
                number=int(item["number"]),
                author=author,
                is_draft=bool(item.get("isDraft")),
                is_fork=head_owner != owner,
                merge_state=str(item.get("mergeStateStatus", "UNKNOWN")).upper(),
                files=files,
            )
        )
    return pulls


def fetch_pull_requests(repo: str, *, runner: Runner) -> list[PullRequest]:
    raw = runner.run(
        [
            "gh",
            "pr",
            "list",
            "--repo",
            repo,
            "--state",
            "open",
            "--limit",
            "50",
            "--json",
            "number,author,isDraft,headRepositoryOwner,mergeStateStatus,files",
        ]
    )
    if not raw.strip():
        return []
    return parse_pull_requests(repo, json.loads(raw))


def discover_repos_with_open_prs(owner: str, *, runner: Runner) -> list[str]:
    raw = runner.run(
        [
            "gh",
            "search",
            "prs",
            "--owner",
            owner,
            "--state",
            "open",
            "--limit",
            "100",
            "--json",
            "repository",
        ]
    )
    if not raw.strip():
        return []
    seen: dict[str, None] = {}
    for item in json.loads(raw):
        name = str((item.get("repository") or {}).get("nameWithOwner", ""))
        if name:
            seen[name] = None
    return list(seen)


def automerge_repo(
    repo: str,
    *,
    trusted: set[str],
    allowlist: set[str],
    live: bool,
    dry_run: bool,
    runner: Runner,
) -> list[dict[str, Any]]:
    enabled = live_repo_enabled(repo, live=live, dry_run=dry_run, allowlist=allowlist)
    results: list[dict[str, Any]] = []
    for pr in fetch_pull_requests(repo, runner=runner):
        verdict = evaluate_pr(pr, trusted=trusted)
        if verdict["decision"] != "auto_merge":
            verdict["action"] = "skipped"
            results.append(verdict)
            continue
        if not enabled:
            verdict["action"] = (
                "would_enable_auto_merge" if dry_run else "blocked_by_live_allowlist"
            )
        else:
            runner.run(
                ["gh", "pr", "merge", str(pr.number), "--repo", repo, "--squash", "--auto"]
            )
            verdict["action"] = "auto_merge_enabled"
        results.append(verdict)
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Auto-merge trusted-author PRs that are safe.")
    parser.add_argument("repos", nargs="*", help="owner/repo targets (default: discover open PRs)")
    parser.add_argument("--owner", default=os.environ.get("PICKET_OWNER", ""))
    parser.add_argument("--live-allowlist", default="config/live_allowlist.txt")
    parser.add_argument("--live", action="store_true", help="merge only for allowlisted repos")
    parser.add_argument("--execute", dest="dry_run", action="store_false")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true", default=True)
    parser.add_argument(
        "--trusted-authors", help="comma-separated; overrides PICKET_TRUSTED_PR_AUTHORS"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = SubprocessRunner()
    trusted = trusted_authors(args.trusted_authors)
    allowlist = load_allowlist(Path(args.live_allowlist))
    repos = list(args.repos)
    if not repos:
        if not args.owner:
            print(
                "error: pass repos as arguments or set PICKET_OWNER to discover them",
                file=sys.stderr,
            )
            return 2
        repos = discover_repos_with_open_prs(args.owner, runner=runner)
    results: list[dict[str, Any]] = []
    for repo in repos:
        try:
            results.extend(
                automerge_repo(
                    repo,
                    trusted=trusted,
                    allowlist=allowlist,
                    live=args.live,
                    dry_run=args.dry_run,
                    runner=runner,
                )
            )
        except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError, ValueError) as exc:
            print(f"warning: skipped {repo}: {exc}", file=sys.stderr)
            results.append({"repo": repo, "action": "error", "decision": "skip", "error": str(exc)})
    json.dump(
        {"trusted_authors": sorted(trusted), "dry_run": args.dry_run, "results": results},
        sys.stdout,
        indent=2,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
