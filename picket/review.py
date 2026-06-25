from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from picket.sec_scan import scan_delta
from picket.tiers import annotate_finding


def load_delta(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"delta file must contain an object: {path}")
    return data


def review_delta(delta: dict[str, Any]) -> dict[str, Any]:
    repo = str(delta["repo"])
    patch = str(delta.get("patch") or "")
    alerts = delta.get("alerts", {})
    if not isinstance(alerts, dict):
        alerts = {}
    normalized_alerts = {
        str(kind): payload if isinstance(payload, list) else [] for kind, payload in alerts.items()
    }
    findings = [annotate_finding(finding) for finding in scan_delta(repo, patch, normalized_alerts)]
    return {
        "repo": repo,
        "base_sha": delta.get("base_sha"),
        "head_sha": delta.get("head_sha"),
        "dry_run": True,
        "findings": findings,
        "proposal": proposal_for_findings(findings),
    }


def proposal_for_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "No findings after sec-scan prefilter; no model context needed."
    tiers = {finding["tier"] for finding in findings}
    if "tier-3" in tiers:
        return "Escalate tier-3 findings; do not write to the repo."
    if tiers == {"tier-1"}:
        return "Prepare patch/minor dependency PR; auto-merge only after green CI."
    return "Prepare PR labeled needs-review; no auto-merge."


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Review fetched deltas in dry-run mode.")
    parser.add_argument("delta", nargs="+", help="Delta JSON file(s) from fetch_delta.sh")
    parser.add_argument("--json", action="store_true", default=True)
    parser.add_argument("--dry-run", action="store_true", default=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    results = [review_delta(load_delta(path)) for path in args.delta]
    json.dump(results, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

