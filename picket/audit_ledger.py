"""The audit-debt ledger: per-repo, per-dimension change gating.

The expensive unit of a deep audit is a (repo, dimension) pair, not a repo. So we
track, per repo per dimension, a content hash of just the files that dimension
reads (see audit_inputs.py). A dimension is re-audited only when (a) its 2-clean
baseline is not yet established, (b) its input hash moved, or (c) it has gone stale
past a floor. Quiet repos cost almost nothing; the budget flows to what changed.

The 4 Sunday sprints pull from the DUE set, risk-ordered (public + prior-findings
first), and `sprint_take` guarantees everything due is covered by the 4th sprint.
"""

from __future__ import annotations

import copy
import json
import math
from datetime import datetime
from pathlib import Path
from typing import Any

from picket.checkpoints import utc_now_iso, write_checkpoints_atomic

DIMENSIONS = ("deps", "secret", "sast", "config")
BASELINE_CLEAN_AUDITS = 2
STALENESS_DAYS = 90
SPRINTS_PER_MONTH = 4

LedgerData = dict[str, Any]


def empty_ledger() -> LedgerData:
    return {"version": 1, "repos": {}}


def load_ledger(path: str | Path) -> LedgerData:
    ledger_path = Path(path)
    if not ledger_path.exists() or ledger_path.stat().st_size == 0:
        return empty_ledger()
    data = json.loads(ledger_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("ledger file must contain a JSON object")
    data.setdefault("version", 1)
    repos = data.setdefault("repos", {})
    if not isinstance(repos, dict):
        raise ValueError("ledger field 'repos' must be an object")
    return data


def save_ledger(path: str | Path, ledger: LedgerData) -> None:
    # Same atomic tmp-then-rename writer the checkpoints use.
    write_checkpoints_atomic(path, ledger)


def _dimension_record(ledger: LedgerData, repo: str, dimension: str) -> dict[str, Any]:
    repo_entry = ledger.get("repos", {}).get(repo, {})
    if not isinstance(repo_entry, dict):
        return {}
    dims = repo_entry.get("dimensions", {})
    record = dims.get(dimension, {}) if isinstance(dims, dict) else {}
    return record if isinstance(record, dict) else {}


def _age_days(last_audited: Any, now: float) -> float:
    """Days since an ISO timestamp; inf if missing/unparseable (so it reads as due)."""
    if not last_audited:
        return float("inf")
    try:
        stamp = datetime.fromisoformat(str(last_audited).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return float("inf")
    return max(0.0, (now - stamp) / 86400.0)


def dimension_due(
    record: dict[str, Any],
    current_hash: str,
    now: float,
    *,
    baseline: int = BASELINE_CLEAN_AUDITS,
    staleness_days: float = STALENESS_DAYS,
) -> tuple[bool, str]:
    """Is this dimension due for a deep audit? Returns (due, reason).

    reason is one of: baseline | changed | stale | clean.
    """
    streak = int(record.get("clean_streak", 0) or 0)
    if streak < baseline:
        return True, "baseline"  # need `baseline` consecutive clean passes first
    if record.get("input_hash") != current_hash:
        return True, "changed"  # the files this dimension reads moved
    if _age_days(record.get("last_audited"), now) >= staleness_days:
        return True, "stale"  # re-check unchanged code against the evolving threat set
    return False, "clean"


def record_audit(
    ledger: LedgerData,
    repo: str,
    dimension: str,
    *,
    input_hash: str,
    findings: list[dict[str, Any]],
    now: str | None = None,
    head_sha: str | None = None,
    risk: dict[str, Any] | None = None,
) -> LedgerData:
    """Return a new ledger with this (repo, dimension) audit recorded.

    Streak logic: findings reset it to 0 (must be fixed + re-confirmed); a clean
    pass on UNCHANGED inputs increments it; a clean pass on CHANGED inputs starts a
    fresh baseline at 1 (new code earns its own 2-clean confidence).
    """
    now = now or utc_now_iso()
    updated = copy.deepcopy(ledger)
    repos = updated.setdefault("repos", {})
    repo_entry = repos.setdefault(repo, {})
    if not isinstance(repo_entry, dict):
        repo_entry = {}
        repos[repo] = repo_entry
    if head_sha is not None:
        repo_entry["head_sha"] = head_sha
    if risk is not None:
        repo_entry["risk"] = risk
    dims = repo_entry.setdefault("dimensions", {})
    if not isinstance(dims, dict):
        dims = {}
        repo_entry["dimensions"] = dims

    previous = dims.get(dimension, {}) if isinstance(dims.get(dimension), dict) else {}
    previous_streak = int(previous.get("clean_streak", 0) or 0)
    if findings:
        streak = 0
    elif previous.get("input_hash") == input_hash:
        streak = previous_streak + 1
    else:
        streak = 1

    dims[dimension] = {
        "input_hash": input_hash,
        "last_audited": now,
        "clean_streak": streak,
        "findings": findings or [],
    }
    return updated


def repo_due_dimensions(
    ledger: LedgerData,
    repo: str,
    current_hashes: dict[str, str],
    now: float,
    **kwargs: Any,
) -> list[tuple[str, str]]:
    """[(dimension, reason), ...] for the dimensions of `repo` that are due."""
    due: list[tuple[str, str]] = []
    for dimension in DIMENSIONS:
        record = _dimension_record(ledger, repo, dimension)
        is_due, reason = dimension_due(record, current_hashes.get(dimension, ""), now, **kwargs)
        if is_due:
            due.append((dimension, reason))
    return due


def risk_key(ledger: LedgerData, repo: str) -> tuple[int, int]:
    """Sort key (descending) so public + prior-findings repos audit first."""
    entry = ledger.get("repos", {}).get(repo, {})
    risk = entry.get("risk", {}) if isinstance(entry, dict) else {}
    public = 1 if risk.get("public") else 0
    prior = int(risk.get("prior_findings", 0) or 0)
    return (public, prior)


def due_set(
    ledger: LedgerData,
    repo_hashes: dict[str, dict[str, str]],
    now: float,
    **kwargs: Any,
) -> list[dict[str, Any]]:
    """repo_hashes is {repo: {dimension: hash}}. Returns the due repos, risk-ordered.

    Each item: {"repo": str, "due_dimensions": [(dimension, reason), ...]}.
    """
    out: list[dict[str, Any]] = []
    for repo, hashes in repo_hashes.items():
        dimensions = repo_due_dimensions(ledger, repo, hashes, now, **kwargs)
        if dimensions:
            out.append({"repo": repo, "due_dimensions": dimensions})
    out.sort(key=lambda item: (risk_key(ledger, item["repo"]), item["repo"]), reverse=True)
    return out


def sprint_take(due_count: int, sprint_index: int, sprints: int = SPRINTS_PER_MONTH) -> int:
    """How many currently-due repos this sprint should take, covering all by the last.

    Sprint 1 takes ceil(N/4), sprint 2 ceil(remaining/3), ... sprint 4 takes all
    that is left. Self-balancing as audited repos drop out of the due set.
    """
    remaining_sprints = max(1, sprints - (max(1, sprint_index) - 1))
    return math.ceil(max(0, due_count) / remaining_sprints)


def sprint_index_for_day(day_of_month: int, sprints: int = SPRINTS_PER_MONTH) -> int:
    """Which sprint a given calendar day belongs to (Nth occurrence of the weekday).

    The Nth Sunday of a month is ((day - 1) // 7) + 1; a 5th Sunday folds onto the
    last sprint (its due set is normally already empty by then).
    """
    nth = ((max(1, day_of_month) - 1) // 7) + 1
    return min(nth, sprints)
