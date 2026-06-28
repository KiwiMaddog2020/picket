"""Escalate patchable Dependabot alerts that have no clean PR to auto-merge.

Picket's auto-merge only resolves a dependency vuln when Dependabot opens a
CLEAN, mergeable PR for it. That step fails three ways, leaving real vulns open
with nothing escalated:

  1. Dependabot won't open a PR for a TRANSITIVE / subdir-lockfile dep.
  2. Its PR goes DIRTY (merge-conflicted) on a major bump, so the auto-merge
     (which requires CLEAN/HAS_HOOKS) skips it.
  3. It opens NO PR at all.

This pass reconciles open Dependabot alerts against open PRs and flags every
PATCHABLE alert (Dependabot knows the fix) that no clean PR covers, then
escalates the batch loudly (Telegram + ntfy + your escalate-cmd). Read-only: it
never merges or edits code, only surfaces the gap.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from picket.apply import Escalator, Runner, SubprocessRunner, load_allowlist
from picket.automerge import MERGEABLE_STATES, PullRequest, fetch_pull_requests
from picket.prefilter import GhClient


def _age_hours(created_at: Any, now: float) -> float:
    """Hours since an alert's ISO-8601 created_at; 0 if missing/unparseable."""
    if not created_at:
        return 0.0
    try:
        stamp = datetime.fromisoformat(str(created_at).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return 0.0
    return max(0.0, (now - stamp) / 3600.0)


def _pr_mentions(pr: PullRequest, package: str) -> bool:
    """A Dependabot PR names the bumped package in its title; match on that."""
    return bool(package) and package.lower() in (pr.title or "").lower()


def orphaned_patchable_alerts(
    alerts: list[dict[str, Any]],
    prs: list[PullRequest],
    now: float,
    *,
    min_age_hours: float = 24.0,
) -> list[dict[str, Any]]:
    """Pure: the patchable Dependabot alerts that no CLEAN PR covers.

    An alert is orphaned when it (a) has a first_patched_version (Dependabot knows
    the fix), (b) is older than min_age_hours (Dependabot had time to open a PR),
    and (c) has no clean, mergeable, non-draft PR mentioning its package. A DIRTY
    PR that mentions the package does NOT cover it (it can't merge), so the alert
    stays orphaned, tagged with a distinct reason.
    """
    out: list[dict[str, Any]] = []
    for alert in alerts:
        vuln = alert.get("security_vulnerability")
        vuln = vuln if isinstance(vuln, dict) else {}
        package = (vuln.get("package") or {}).get("name") or ""
        patched = (vuln.get("first_patched_version") or {}).get("identifier")
        if not package or not patched:
            continue  # not patchable: Dependabot has no fix, out of this pass's scope
        if _age_hours(alert.get("created_at"), now) < min_age_hours:
            continue  # too fresh: give Dependabot its chance to open a PR first
        mentioning = [pr for pr in prs if _pr_mentions(pr, package)]
        covered = any(pr.merge_state in MERGEABLE_STATES and not pr.is_draft for pr in mentioning)
        if covered:
            continue  # a clean PR exists; the auto-merge will land it
        out.append(
            {
                "number": alert.get("number"),
                "package": package,
                "patched_version": patched,
                "severity": str(vuln.get("severity") or "unknown"),
                "url": alert.get("html_url"),
                "manifest": (alert.get("dependency") or {}).get("manifest_path"),
                "reason": "dirty_or_blocked_pr" if mentioning else "no_pr",
            }
        )
    return out


def orphans_for_repo(
    repo: str,
    *,
    client: GhClient,
    runner: Runner,
    now: float,
    min_age_hours: float = 24.0,
) -> list[dict[str, Any]]:
    """Fetch a repo's open Dependabot alerts + open PRs, return its orphans."""
    alerts = client.alerts(repo, "dependabot")
    prs = fetch_pull_requests(repo, runner=runner)
    orphans = orphaned_patchable_alerts(alerts, prs, now, min_age_hours=min_age_hours)
    for orphan in orphans:
        orphan["repo"] = repo
    return orphans


def render_orphan_summary(orphans: list[dict[str, Any]]) -> str:
    """Plain-text escalation body (Picket sends plain text, not HTML)."""
    lines = [f"Picket: {len(orphans)} patchable dep(s) stuck (fix exists, no clean PR):"]
    for orphan in orphans:
        repo = str(orphan.get("repo", "?")).split("/")[-1]
        why = "no PR" if orphan.get("reason") == "no_pr" else "PR conflicted"
        lines.append(
            f"  {repo}: {orphan.get('package')} -> {orphan.get('patched_version')} "
            f"[{orphan.get('severity')}] ({why})"
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Escalate patchable Dependabot alerts with no clean PR."
    )
    parser.add_argument("repos", nargs="*", help="owner/repo targets (default: the live allowlist)")
    parser.add_argument("--live-allowlist", default="config/live_allowlist.txt")
    parser.add_argument("--min-age-hours", type=float, default=24.0)
    parser.add_argument("--ntfy-topic", default=os.environ.get("PICKET_NTFY_TOPIC"))
    parser.add_argument("--escalate-cmd", default=os.environ.get("PICKET_ESCALATE_CMD"))
    parser.add_argument("--live", action="store_true", help="unused; accepted for run-once parity")
    parser.add_argument("--execute", dest="dry_run", action="store_false")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true", default=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    # parse_known_args so run-once.sh can forward its full flag set (e.g.
    # --write-checkpoint) without this pass choking on flags it does not use.
    args, _ = build_parser().parse_known_args(argv)
    runner = SubprocessRunner()
    client = GhClient()
    repos = args.repos or sorted(load_allowlist(Path(args.live_allowlist)))
    now = time.time()
    orphans: list[dict[str, Any]] = []
    for repo in repos:
        try:
            orphans.extend(
                orphans_for_repo(
                    repo, client=client, runner=runner, now=now, min_age_hours=args.min_age_hours
                )
            )
        except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError, ValueError) as exc:
            # One unreadable repo must not abort the sweep.
            print(f"orphan-alerts: warning: skipped {repo}: {exc}", file=sys.stderr)

    if orphans:
        escalator = Escalator(
            dry_run=args.dry_run,
            ntfy_topic=args.ntfy_topic,
            escalate_cmd=args.escalate_cmd,
            telegram_token=os.environ.get("PICKET_TELEGRAM_BOT_TOKEN"),
            telegram_chat_id=os.environ.get("PICKET_TELEGRAM_CHAT_ID"),
            runner=runner,
        )
        repo_count = len({orphan["repo"] for orphan in orphans})
        summary = f"{len(orphans)} patchable dep(s) with no clean PR across {repo_count} repo(s)"
        escalator.escalate_summary(render_orphan_summary(orphans), summary)

    json.dump({"dry_run": args.dry_run, "orphans": orphans}, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
