from __future__ import annotations

import copy
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CheckpointData = dict[str, Any]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def empty_checkpoints() -> CheckpointData:
    return {"repos": {}}


def load_checkpoints(path: str | Path) -> CheckpointData:
    checkpoint_path = Path(path)
    if not checkpoint_path.exists() or checkpoint_path.stat().st_size == 0:
        return empty_checkpoints()

    data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("checkpoint file must contain a JSON object")
    repos = data.setdefault("repos", {})
    if not isinstance(repos, dict):
        raise ValueError("checkpoint field 'repos' must be an object")
    return data


def repo_checkpoint(checkpoints: CheckpointData, repo: str) -> dict[str, Any]:
    repos = checkpoints.get("repos", {})
    if not isinstance(repos, dict):
        return {}
    entry = repos.get(repo, {})
    return entry if isinstance(entry, dict) else {}


def normalized_alert_cursors(entry: dict[str, Any]) -> dict[str, str]:
    raw = entry.get("last_alert_cursor", {})
    if not isinstance(raw, dict):
        return {}
    return {str(key): str(value) for key, value in raw.items() if value is not None}


def update_repo_checkpoint(
    checkpoints: CheckpointData,
    repo: str,
    *,
    last_sha: str | None = None,
    last_pushed_at: str | None = None,
    alert_cursors: dict[str, str] | None = None,
    last_run: str | None = None,
) -> CheckpointData:
    updated = copy.deepcopy(checkpoints)
    repos = updated.setdefault("repos", {})
    if not isinstance(repos, dict):
        raise ValueError("checkpoint field 'repos' must be an object")

    entry = repos.setdefault(repo, {})
    if not isinstance(entry, dict):
        entry = {}
        repos[repo] = entry

    original_entry = copy.deepcopy(entry)
    if last_sha is not None:
        entry["last_sha"] = last_sha
    if last_pushed_at is not None:
        entry["last_pushed_at"] = last_pushed_at
    if alert_cursors is not None:
        entry["last_alert_cursor"] = dict(sorted(alert_cursors.items()))

    unchanged = True
    if last_sha is not None and original_entry.get("last_sha") != last_sha:
        unchanged = False
    if last_pushed_at is not None and original_entry.get("last_pushed_at") != last_pushed_at:
        unchanged = False
    if alert_cursors is not None and original_entry.get("last_alert_cursor") != dict(
        sorted(alert_cursors.items())
    ):
        unchanged = False

    if unchanged and last_run is None and original_entry.get("last_run"):
        entry["last_run"] = original_entry["last_run"]
        return updated
    entry["last_run"] = last_run or utc_now_iso()
    return updated


def write_checkpoints_atomic(path: str | Path, checkpoints: CheckpointData) -> None:
    checkpoint_path = Path(path)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(checkpoints, indent=2, sort_keys=True) + "\n"
    tmp_path = checkpoint_path.with_name(f".{checkpoint_path.name}.{uuid.uuid4().hex}.tmp")
    tmp_path.write_text(payload, encoding="utf-8")
    os.replace(tmp_path, checkpoint_path)
