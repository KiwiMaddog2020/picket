from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from picket.checkpoints import load_checkpoints, normalized_alert_cursors, repo_checkpoint
from picket.prefilter import ALERT_KINDS, GhClient


def run_git(repo_dir: Path, args: list[str]) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_dir), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def slug(repo: str) -> str:
    return repo.replace("/", "__")


def default_repo_dir(repo: str) -> Path:
    return Path("state/repos") / slug(repo)


def collect_alerts(client: GhClient, repo: str) -> dict[str, list[dict[str, Any]]]:
    return {kind: client.alerts(repo, kind) for kind in ALERT_KINDS}


def fetch_delta(
    *,
    repo: str,
    repo_dir: Path,
    checkpoint_path: Path,
    gh_bin: str,
) -> dict[str, Any]:
    checkpoints = load_checkpoints(checkpoint_path)
    checkpoint = repo_checkpoint(checkpoints, repo)
    base_sha = checkpoint.get("last_sha")
    if not base_sha:
        raise ValueError(f"checkpoint for {repo} has no last_sha; seed before fetching deltas")

    run_git(repo_dir, ["fetch", "--quiet", "origin"])
    head_sha = run_git(repo_dir, ["rev-parse", "HEAD"]).strip()
    files = [
        line
        for line in run_git(repo_dir, ["diff", "--name-only", f"{base_sha}..HEAD"]).splitlines()
        if line
    ]
    patch = run_git(repo_dir, ["diff", "--no-ext-diff", "--unified=80", f"{base_sha}..HEAD"])
    alerts = collect_alerts(GhClient(gh_bin), repo)

    return {
        "repo": repo,
        "repo_dir": str(repo_dir),
        "base_sha": base_sha,
        "head_sha": head_sha,
        "files": files,
        "patch": patch,
        "alerts": alerts,
        "previous_alert_cursors": normalized_alert_cursors(checkpoint),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch a minimal git diff and current alert payloads."
    )
    parser.add_argument("--repo", required=True)
    parser.add_argument("--repo-dir")
    parser.add_argument("--checkpoint", default="state/checkpoints.json")
    parser.add_argument("--output-dir", default="state/deltas")
    parser.add_argument("--gh-bin", default="gh")
    parser.add_argument("--dry-run", action="store_true", default=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_dir = Path(args.repo_dir) if args.repo_dir else default_repo_dir(args.repo)
    delta = fetch_delta(
        repo=args.repo,
        repo_dir=repo_dir,
        checkpoint_path=Path(args.checkpoint),
        gh_bin=args.gh_bin,
    )
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{slug(args.repo)}.json"
    output_path.write_text(json.dumps(delta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    json.dump({"delta": str(output_path), "repo": args.repo}, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
