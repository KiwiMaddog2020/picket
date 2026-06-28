from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from picket.checkpoints import (
    CheckpointData,
    load_checkpoints,
    update_repo_checkpoint,
    write_checkpoints_atomic,
)
from picket.tiers import Tier


class Runner(Protocol):
    def run(
        self,
        command: list[str],
        *,
        cwd: str | Path | None = None,
        input_text: str | None = None,
    ) -> str: ...


@dataclass
class SubprocessRunner:
    def run(
        self,
        command: list[str],
        *,
        cwd: str | Path | None = None,
        input_text: str | None = None,
    ) -> str:
        completed = subprocess.run(
            command,
            cwd=cwd,
            input=input_text,
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()


@dataclass
class Escalator:
    dry_run: bool = True
    ntfy_topic: str | None = None
    escalate_cmd: str | None = None
    telegram_token: str | None = None
    telegram_chat_id: str | None = None
    runner: Runner = field(default_factory=SubprocessRunner)
    events: list[dict[str, Any]] = field(default_factory=list)
    notifications: list[str] = field(default_factory=list)

    def notify(self, text: str) -> dict[str, Any]:
        """Send a 'needs your review' heads-up to Telegram, if configured.

        Records every message (so dry-runs show what *would* be sent) but only
        actually calls Telegram on a live run with a token + chat id present.
        """
        self.notifications.append(text)
        if self.dry_run:
            return {"notified": False, "reason": "dry_run"}
        if not (self.telegram_token and self.telegram_chat_id):
            return {"notified": False, "reason": "telegram_not_configured"}
        self.runner.run(
            [
                "curl",
                "-fsS",
                "-X",
                "POST",
                f"https://api.telegram.org/bot{self.telegram_token}/sendMessage",
                "--data-urlencode",
                f"chat_id={self.telegram_chat_id}",
                "--data-urlencode",
                f"text={text}",
            ]
        )
        return {"notified": True}

    def escalate_summary(self, text: str, summary: str) -> dict[str, Any]:
        """A batched loud escalation: Telegram body + ntfy + an escalate-cmd call.

        Like escalate(), but for a pre-rendered digest with its own one-line
        summary (used by the orphaned-alert pass), not a single tier-3 finding.
        """
        self.notify(text)
        if self.dry_run:
            return {"action": "would_escalate", "message": summary}
        if self.ntfy_topic:
            self.runner.run(["curl", "-fsS", "-d", summary, self.ntfy_topic])
        if self.escalate_cmd:
            self.runner.run([self.escalate_cmd, summary])
        return {"action": "escalated", "message": summary}

    def escalate(self, repo: str, finding: dict[str, Any]) -> dict[str, Any]:
        message = f"Picket: review needed (tier-3) in {repo} — {finding.get('title', 'untitled')}"
        self.events.append({"repo": repo, "message": message, "finding": finding})
        return self.escalate_summary(message, message)


def load_allowlist(path: str | Path) -> set[str]:
    allowlist_path = Path(path)
    if not allowlist_path.exists():
        return set()
    repos: set[str] = set()
    for line in allowlist_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            repos.add(stripped)
    return repos


def load_review(path: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    raise ValueError("review JSON must be an object or list of objects")


def branch_name(repo: str, head_sha: str | None, tier: str) -> str:
    repo_slug = repo.replace("/", "-").lower()
    suffix = (head_sha or "delta")[:12]
    return f"picket/{tier}/{repo_slug}-{suffix}"


def repo_dir_for_review(review: dict[str, Any]) -> str | None:
    value = review.get("repo_dir")
    return str(value) if value else None


def live_repo_enabled(repo: str, *, live: bool, dry_run: bool, allowlist: set[str]) -> bool:
    return live and not dry_run and repo in allowlist


def _changed_files_for_finding(finding: dict[str, Any]) -> list[str]:
    files = finding.get("files")
    if isinstance(files, list):
        return [str(file) for file in files if file]
    file = finding.get("file")
    return [str(file)] if file else []


def create_pr_for_finding(
    *,
    review: dict[str, Any],
    finding: dict[str, Any],
    tier: Tier,
    runner: Runner,
) -> dict[str, Any]:
    repo = str(review["repo"])
    repo_dir = repo_dir_for_review(review)
    fix_patch = finding.get("fix_patch")
    if not repo_dir or not fix_patch:
        return {
            "action": "blocked_missing_fix_patch",
            "repo": repo,
            "tier": tier.value,
            "reason": "live PR creation requires repo_dir and fix_patch",
        }

    branch = branch_name(repo, str(review.get("head_sha") or ""), tier.value)
    runner.run(["git", "checkout", "-B", branch], cwd=repo_dir)
    runner.run(["git", "apply", "-"], cwd=repo_dir, input_text=str(fix_patch))
    changed_files = _changed_files_for_finding(finding)
    if changed_files:
        runner.run(["git", "add", "--", *changed_files], cwd=repo_dir)
    else:
        changed = runner.run(["git", "diff", "--name-only"], cwd=repo_dir).splitlines()
        if changed:
            runner.run(["git", "add", "--", *changed], cwd=repo_dir)
    runner.run(
        ["git", "commit", "-m", f"fix(security): {finding.get('title', 'apply fix')}"],
        cwd=repo_dir,
    )
    runner.run(["git", "push", "--set-upstream", "origin", branch], cwd=repo_dir)
    labels = ["picket", tier.value]
    if tier is Tier.TIER_2:
        labels.append("needs-review")
    for label in labels:
        # Ensure the label exists, so `gh pr create --label` never fails on a repo
        # that has never received a picket PR. Idempotent + best-effort.
        try:
            runner.run(["gh", "label", "create", label, "--repo", repo, "--force"])
        except subprocess.CalledProcessError:
            pass
    pr_url = runner.run(
        [
            "gh",
            "pr",
            "create",
            "--repo",
            repo,
            "--head",
            branch,
            "--title",
            f"picket: {finding.get('title', 'security fix')}",
            "--body",
            str(finding.get("body") or finding.get("tier_reason") or "Generated by picket."),
            "--label",
            ",".join(labels),
        ]
    )
    result = {
        "action": "created_pr",
        "repo": repo,
        "tier": tier.value,
        "pr": pr_url,
        "branch": branch,
    }
    if finding.get("auto_merge_candidate") is True:
        runner.run(["gh", "pr", "merge", pr_url, "--repo", repo, "--auto", "--squash"])
        result["auto_merge"] = "enabled_on_green_ci"
    return result


def checkpoint_for_review(checkpoints: CheckpointData, review: dict[str, Any]) -> CheckpointData:
    repo = str(review["repo"])
    return update_repo_checkpoint(
        checkpoints,
        repo,
        last_sha=str(review.get("head_sha") or "") or None,
        last_pushed_at=str(review.get("pushed_at") or "") or None,
        alert_cursors=review.get("alert_cursors")
        if isinstance(review.get("alert_cursors"), dict)
        else None,
    )


def apply_review(
    review: dict[str, Any],
    *,
    allowlist: set[str],
    live: bool = False,
    dry_run: bool = True,
    runner: Runner | None = None,
    escalator: Escalator | None = None,
) -> dict[str, Any]:
    runner = runner or SubprocessRunner()
    escalator = escalator or Escalator(dry_run=dry_run, runner=runner)
    repo = str(review["repo"])
    enabled = live_repo_enabled(repo, live=live, dry_run=dry_run, allowlist=allowlist)
    results: list[dict[str, Any]] = []

    for finding in review.get("findings", []):
        if not isinstance(finding, dict):
            continue
        tier = Tier(str(finding["tier"]))
        if tier is Tier.TIER_3:
            results.append(escalator.escalate(repo, finding))
            continue

        if not enabled:
            action = "would_create_pr" if dry_run else "blocked_by_live_allowlist"
            results.append({"action": action, "repo": repo, "tier": tier.value})
        else:
            results.append(
                create_pr_for_finding(
                    review=review,
                    finding=finding,
                    tier=tier,
                    runner=runner,
                )
            )

        if tier is Tier.TIER_2:
            escalator.notify(
                f"Picket: review needed in {repo} — {finding.get('title', 'a security finding')}"
            )

    return {
        "repo": repo,
        "dry_run": dry_run,
        "live": live,
        "allowlisted": repo in allowlist,
        "actions": results,
    }


def apply_reviews(
    reviews: list[dict[str, Any]],
    *,
    checkpoint_path: Path,
    allowlist_path: Path,
    live: bool,
    dry_run: bool,
    write_checkpoint: bool,
    runner: Runner | None = None,
    escalator: Escalator | None = None,
) -> dict[str, Any]:
    allowlist = load_allowlist(allowlist_path)
    results = [
        apply_review(
            review,
            allowlist=allowlist,
            live=live,
            dry_run=dry_run,
            runner=runner,
            escalator=escalator,
        )
        for review in reviews
    ]
    if write_checkpoint and not dry_run:
        checkpoints = load_checkpoints(checkpoint_path)
        for review in reviews:
            checkpoints = checkpoint_for_review(checkpoints, review)
        write_checkpoints_atomic(checkpoint_path, checkpoints)

    return {"results": results, "checkpoint_written": write_checkpoint and not dry_run}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Apply or escalate reviewed security deltas.")
    parser.add_argument("review", nargs="+", help="Review JSON from review_delta.py")
    parser.add_argument("--checkpoint", default="state/checkpoints.json")
    parser.add_argument("--live-allowlist", default="config/live_allowlist.txt")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Allow repo writes only for allowlisted repos",
    )
    parser.add_argument("--execute", dest="dry_run", action="store_false")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true", default=True)
    parser.add_argument("--write-checkpoint", action="store_true")
    parser.add_argument("--ntfy-topic")
    parser.add_argument("--escalate-cmd")
    parser.add_argument("--telegram-token", default=os.environ.get("PICKET_TELEGRAM_BOT_TOKEN"))
    parser.add_argument("--telegram-chat-id", default=os.environ.get("PICKET_TELEGRAM_CHAT_ID"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    reviews: list[dict[str, Any]] = []
    for review_path in args.review:
        reviews.extend(load_review(review_path))
    runner = SubprocessRunner()
    escalator = Escalator(
        dry_run=args.dry_run,
        ntfy_topic=args.ntfy_topic,
        escalate_cmd=args.escalate_cmd,
        telegram_token=args.telegram_token,
        telegram_chat_id=args.telegram_chat_id,
        runner=runner,
    )
    result = apply_reviews(
        reviews,
        checkpoint_path=Path(args.checkpoint),
        allowlist_path=Path(args.live_allowlist),
        live=args.live,
        dry_run=args.dry_run,
        write_checkpoint=args.write_checkpoint,
        runner=runner,
        escalator=escalator,
    )
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
