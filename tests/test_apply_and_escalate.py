from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from picket.apply import Escalator, apply_review, checkpoint_for_review, load_allowlist
from picket.checkpoints import empty_checkpoints, write_checkpoints_atomic


@dataclass
class RecordingRunner:
    commands: list[list[str]] = field(default_factory=list)

    def run(
        self,
        command: list[str],
        *,
        cwd: str | Path | None = None,
        input_text: str | None = None,
    ) -> str:
        self.commands.append(command)
        if command[:3] == ["gh", "pr", "create"]:
            return "https://github.com/octocat/example/pull/1"
        if command[:3] == ["git", "diff", "--name-only"]:
            return "requirements.txt\n"
        return ""


def tier_1_review() -> dict[str, object]:
    return {
        "repo": "octocat/example",
        "head_sha": "abcdef123456",
        "findings": [
            {
                "tier": "tier-1",
                "auto_merge_candidate": True,
                "title": "django dependency bump",
                "file": "requirements.txt",
                "fix_patch": "diff --git a/requirements.txt b/requirements.txt\n",
            }
        ],
    }


def test_empty_live_allowlist_blocks_repo_writes_even_with_live_flag(tmp_path: Path) -> None:
    allowlist = tmp_path / "live_allowlist.txt"
    allowlist.write_text("\n", encoding="utf-8")
    runner = RecordingRunner()

    result = apply_review(
        tier_1_review(),
        allowlist=load_allowlist(allowlist),
        live=True,
        dry_run=False,
        runner=runner,
    )

    assert runner.commands == []
    assert result["actions"] == [
        {"action": "blocked_by_live_allowlist", "repo": "octocat/example", "tier": "tier-1"}
    ]


def test_tier_1_allowed_repo_creates_pr_and_enables_auto_merge_on_green_ci() -> None:
    runner = RecordingRunner()

    result = apply_review(
        {**tier_1_review(), "repo_dir": "/tmp/example"},
        allowlist={"octocat/example"},
        live=True,
        dry_run=False,
        runner=runner,
    )

    assert result["actions"][0]["action"] == "created_pr"
    assert result["actions"][0]["auto_merge"] == "enabled_on_green_ci"
    assert any(command[:3] == ["gh", "pr", "create"] for command in runner.commands)
    assert any(
        command[:3] == ["gh", "pr", "merge"] and "--auto" in command
        for command in runner.commands
    )


def test_secret_finding_escalates_and_never_creates_pr() -> None:
    runner = RecordingRunner()
    escalator = Escalator(dry_run=False, runner=runner)
    review = {
        "repo": "octocat/example",
        "head_sha": "abcdef123456",
        "findings": [{"tier": "tier-3", "title": "Secret scanning alert", "secret": True}],
    }

    result = apply_review(
        review,
        allowlist={"octocat/example"},
        live=True,
        dry_run=False,
        runner=runner,
        escalator=escalator,
    )

    assert result["actions"][0]["action"] == "escalated"
    assert escalator.events
    assert not any(command[:3] == ["gh", "pr", "create"] for command in runner.commands)
    assert not any(command[:3] == ["gh", "pr", "merge"] for command in runner.commands)


def test_checkpoint_write_is_idempotent_for_same_review(tmp_path: Path) -> None:
    checkpoint = tmp_path / "checkpoints.json"
    write_checkpoints_atomic(checkpoint, empty_checkpoints())
    review = {
        "repo": "octocat/example",
        "head_sha": "abcdef123456",
        "pushed_at": "2026-06-20T00:00:00Z",
        "alert_cursors": {"dependabot": "dependabot:2026-06-20T00:00:00Z:7"},
        "findings": [],
    }

    first = checkpoint_for_review(json.loads(checkpoint.read_text(encoding="utf-8")), review)
    write_checkpoints_atomic(checkpoint, first)
    first_payload = checkpoint.read_text(encoding="utf-8")
    second = checkpoint_for_review(json.loads(first_payload), review)
    write_checkpoints_atomic(checkpoint, second)

    assert checkpoint.read_text(encoding="utf-8") == first_payload


def test_tier_1_without_auto_merge_candidate_creates_pr_but_does_not_merge() -> None:
    runner = RecordingRunner()
    review = {
        "repo": "octocat/example",
        "head_sha": "abcdef123456",
        "repo_dir": "/tmp/example",
        "findings": [
            {
                "tier": "tier-1",
                "auto_merge_candidate": False,
                "title": "low-risk config finding",
                "file": "config.yml",
                "fix_patch": "diff --git a/config.yml b/config.yml\n",
            }
        ],
    }

    result = apply_review(
        review,
        allowlist={"octocat/example"},
        live=True,
        dry_run=False,
        runner=runner,
    )

    assert result["actions"][0]["action"] == "created_pr"
    assert "auto_merge" not in result["actions"][0]
    assert not any(command[:3] == ["gh", "pr", "merge"] for command in runner.commands)
