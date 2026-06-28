"""The rolling deep-audit sprint: one of four Sunday 3am passes per month.

Each sprint: cheaply hash every live repo's per-dimension inputs (git-tree blob
SHAs), ask the ledger which (repo, dimension) pairs are DUE, take this sprint's
risk-ordered slice (sprint_take guarantees all-due-covered by the 4th Sunday),
deep-audit only that slice, record results to the ledger, run the tiered fix
proposer (shadow-first), and send one digest to Telegram + a FLEET decision.

Everything expensive is gated by the ledger, so quiet repos cost a single tree
call and the budget flows to what actually changed since last time.
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

from picket.apply import Escalator, SubprocessRunner, load_allowlist
from picket.audit_inputs import dimension_hashes, tree_entries
from picket.audit_ledger import (
    due_set,
    load_ledger,
    record_audit,
    save_ledger,
    sprint_index_for_day,
    sprint_take,
)
from picket.auditors import audit_repo
from picket.fix_proposer import propose_fixes
from picket.prefilter import GhClient


def _gh_safe(client: Any, path: str) -> Any | None:
    try:
        return client.run_json(["api", path])
    except (subprocess.CalledProcessError, json.JSONDecodeError, ValueError):
        return None


def repo_audit_meta(client: Any, repo: str) -> dict[str, Any]:
    """Default branch, visibility, and HEAD sha for a repo (best-effort)."""
    meta = _gh_safe(client, f"/repos/{repo}") or {}
    default_branch = str(meta.get("default_branch") or "main")
    public = meta.get("visibility") == "public" or meta.get("private") is False
    head = _gh_safe(client, f"/repos/{repo}/commits/{default_branch}") or {}
    head_sha = str(head.get("sha") or "") if isinstance(head, dict) else ""
    return {"default_branch": default_branch, "public": bool(public), "head_sha": head_sha}


def collect_inputs(
    client: Any, repos: list[str]
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, Any]], dict[str, list[tuple[str, str]]]]:
    """For every repo: its per-dimension hashes, its meta, and its tree entries."""
    repo_hashes: dict[str, dict[str, str]] = {}
    repo_meta: dict[str, dict[str, Any]] = {}
    repo_entries: dict[str, list[tuple[str, str]]] = {}
    for repo in repos:
        try:
            meta = repo_audit_meta(client, repo)
            entries = tree_entries(client, repo, meta["head_sha"]) if meta["head_sha"] else []
            repo_hashes[repo] = dimension_hashes(entries, meta["head_sha"])
            repo_meta[repo] = meta
            repo_entries[repo] = entries
        except (subprocess.CalledProcessError, json.JSONDecodeError, ValueError, KeyError) as exc:
            print(f"audit-sprint: warning: skipped {repo} ({type(exc).__name__})", file=sys.stderr)
    return repo_hashes, repo_meta, repo_entries


def render_audit_digest(
    report: dict[str, list[dict[str, Any]]],
    *,
    sprint_index: int,
    repos_audited: list[str],
    shadow: bool,
) -> str:
    badge = " (shadow: nothing merged)" if shadow else ""
    lines = [
        f"🔍 Audit sprint {sprint_index}/4{badge}",
        f"{len(repos_audited)} repo(s) deep-swept this pass",
        "─" * 15,
    ]

    def section(emoji: str, label: str, items: list[dict[str, Any]], key: Any) -> None:
        if not items:
            return
        lines.append(f"{emoji} {label} ({len(items)})")
        for item in items[:12]:
            lines.append("   " + str(key(item)))
        if len(items) > 12:
            lines.append(f"   +{len(items) - 12} more")

    section("🛠", "Fixes proposed", report.get("proposed", []), lambda p: p["summary"])
    section(
        "🔁",
        "ROTATE these credentials (I can't)",
        report.get("rotations", []),
        lambda p: f"{p['finding'].get('repo')}: {p['finding'].get('title')}",
    )
    section("📣", "Escalated for you", report.get("escalations", []), lambda p: p["summary"])
    deferred = report.get("deferred", [])
    if deferred:
        lines.append(f"📦 {len(deferred)} dep alert(s), handled by the auto-merge/orphan layer")
    total = sum(len(report.get(k, [])) for k in ("proposed", "rotations", "escalations"))
    if total == 0:
        lines.append("✅ clean across the swept repos")
    return "\n".join(lines)


def run_sprint(
    *,
    client: Any,
    runner: Any,
    escalator: Escalator,
    allowlist_path: str | Path,
    ledger_path: str | Path,
    sprint_index: int | None = None,
    day_of_month: int | None = None,
    shadow: bool = True,
    deep: bool = False,
    now: float | None = None,
    drafter: Any = None,
    self_checker: Any = None,
) -> dict[str, Any]:
    now = now or time.time()
    repos = sorted(load_allowlist(allowlist_path))
    ledger = load_ledger(ledger_path)

    repo_hashes, repo_meta, repo_entries = collect_inputs(client, repos)
    due = due_set(ledger, repo_hashes, now)
    if sprint_index is None:
        sprint_index = sprint_index_for_day(day_of_month or datetime.now().day)
    take = sprint_take(len(due), sprint_index)
    this_sprint = due[:take]

    all_findings: list[dict[str, Any]] = []
    for item in this_sprint:
        repo = item["repo"]
        dimensions = [dimension for dimension, _reason in item["due_dimensions"]]
        meta = repo_meta.get(repo, {})
        results = audit_repo(
            repo,
            dimensions,
            client=client,
            entries=repo_entries.get(repo, []),
            default_branch=meta.get("default_branch", "main"),
            deep=deep,
        )
        repo_finding_count = sum(len(found) for found in results.values())
        for dimension, found in results.items():
            ledger = record_audit(
                ledger,
                repo,
                dimension,
                input_hash=repo_hashes[repo][dimension],
                findings=found,
                head_sha=meta.get("head_sha"),
                risk={"public": meta.get("public", False), "prior_findings": repo_finding_count},
            )
            all_findings.extend(found)

    fix_kwargs: dict[str, Any] = {}
    if drafter is not None:
        fix_kwargs["drafter"] = drafter
    if self_checker is not None:
        fix_kwargs["self_checker"] = self_checker
    report = propose_fixes(
        all_findings, client=client, runner=runner, shadow=shadow, **fix_kwargs
    )
    save_ledger(ledger_path, ledger)

    audited = [item["repo"] for item in this_sprint]
    digest = render_audit_digest(
        report, sprint_index=sprint_index, repos_audited=audited, shadow=shadow
    )
    summary = (
        f"audit sprint {sprint_index}/4: {len(audited)} repos, "
        f"{len(report['proposed'])} fixes proposed, {len(report['rotations'])} to rotate"
    )
    escalator.escalate_summary(digest, summary)

    return {
        "sprint_index": sprint_index,
        "due_total": len(due),
        "audited": audited,
        "shadow": shadow,
        "counts": {key: len(value) for key, value in report.items()},
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a rolling deep-audit sprint.")
    parser.add_argument("--live-allowlist", default="config/live_allowlist.txt")
    parser.add_argument("--ledger", default="state/audit-ledger.json")
    parser.add_argument("--sprint-index", type=int, default=None)
    parser.add_argument("--deep", action="store_true", help="content-sweep where scanning is off")
    parser.add_argument("--shadow", dest="shadow", action="store_true", default=True)
    parser.add_argument(
        "--go-live", dest="shadow", action="store_false", help="actually open/merge fix PRs"
    )
    parser.add_argument("--no-notify", action="store_true", help="compute but do not send a digest")
    parser.add_argument("--ntfy-topic", default=os.environ.get("PICKET_NTFY_TOPIC"))
    parser.add_argument("--escalate-cmd", default=os.environ.get("PICKET_ESCALATE_CMD"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = SubprocessRunner()
    client = GhClient()
    escalator = Escalator(
        dry_run=args.no_notify,  # a real sprint still notifies even when fixes are shadow
        ntfy_topic=args.ntfy_topic,
        escalate_cmd=args.escalate_cmd,
        telegram_token=os.environ.get("PICKET_TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=os.environ.get("PICKET_TELEGRAM_CHAT_ID"),
        runner=runner,
    )
    result = run_sprint(
        client=client,
        runner=runner,
        escalator=escalator,
        allowlist_path=args.live_allowlist,
        ledger_path=args.ledger,
        sprint_index=args.sprint_index,
        shadow=args.shadow,
        deep=args.deep,
    )
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
