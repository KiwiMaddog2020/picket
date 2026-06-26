from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from picket.automerge import (
    PullRequest,
    automerge_repo,
    evaluate_pr,
    file_is_sensitive,
    has_failing_check,
    normalize_author,
    parse_pull_requests,
    trusted_authors,
)

TRUSTED = {"octocat", "dependabot[bot]"}


def clean_pr(**overrides: object) -> PullRequest:
    base: dict[str, object] = {
        "repo": "octocat/example",
        "number": 1,
        "author": "octocat",
        "is_draft": False,
        "is_fork": False,
        "failing_check": False,
        "conflicting": False,
        "files": ("README.md", "src/app.py"),
    }
    base.update(overrides)
    return PullRequest(**base)  # type: ignore[arg-type]


def test_trusted_clean_pr_auto_merges() -> None:
    verdict = evaluate_pr(clean_pr(), trusted=TRUSTED)
    assert verdict["decision"] == "auto_merge"
    assert verdict["reasons"] == []


def test_untrusted_author_is_skipped() -> None:
    verdict = evaluate_pr(clean_pr(author="randoperson"), trusted=TRUSTED)
    assert verdict["decision"] == "skip"
    assert "untrusted_author" in verdict["reasons"]


def test_fork_is_skipped_even_for_trusted_author() -> None:
    assert "fork" in evaluate_pr(clean_pr(is_fork=True), trusted=TRUSTED)["reasons"]


def test_draft_is_skipped() -> None:
    assert "draft" in evaluate_pr(clean_pr(is_draft=True), trusted=TRUSTED)["reasons"]


def test_failing_checks_skip() -> None:
    reasons = evaluate_pr(clean_pr(failing_check=True), trusted=TRUSTED)["reasons"]
    assert "failing_checks" in reasons


def test_merge_conflict_skips() -> None:
    assert "merge_conflict" in evaluate_pr(clean_pr(conflicting=True), trusted=TRUSTED)["reasons"]


def test_tier3_path_skips_even_for_trusted_author() -> None:
    verdict = evaluate_pr(clean_pr(files=("src/auth/jwt.py",)), trusted=TRUSTED)
    assert verdict["decision"] == "skip"
    assert "tier3_paths" in verdict["reasons"]
    assert verdict["sensitive_files"] == ["src/auth/jwt.py"]


def test_dependabot_is_trusted_when_opted_in() -> None:
    verdict = evaluate_pr(clean_pr(author="dependabot[bot]"), trusted=TRUSTED)
    assert verdict["decision"] == "auto_merge"


def test_file_is_sensitive_matches_auth_secret_payment_only() -> None:
    assert file_is_sensitive("src/auth/login.ts")
    assert file_is_sensitive("config/secrets.yml")
    assert file_is_sensitive("billing/stripe.py")
    assert not file_is_sensitive("README.md")
    assert not file_is_sensitive("src/render.py")


def test_has_failing_check_treats_pending_and_empty_as_passing() -> None:
    assert has_failing_check([{"conclusion": "FAILURE"}])
    assert has_failing_check([{"state": "ERROR"}])
    assert not has_failing_check([{"conclusion": "SUCCESS"}, {"conclusion": "NEUTRAL"}])
    assert not has_failing_check([])


def test_trusted_authors_defaults_to_dependabot_and_honours_override() -> None:
    assert trusted_authors("") == {"dependabot[bot]"}
    assert trusted_authors("a, b ,c") == {"a", "b", "c"}


def test_normalize_author_canonicalises_bot_logins() -> None:
    assert normalize_author("app/dependabot") == "dependabot[bot]"
    assert normalize_author("app/renovate") == "renovate[bot]"
    assert normalize_author("octocat") == "octocat"


def test_parse_normalizes_app_dependabot_and_matches_trusted_set() -> None:
    payload = [
        {
            "number": 4,
            "author": {"login": "app/dependabot"},
            "isDraft": False,
            "headRepositoryOwner": {"login": "octocat"},
            "mergeable": "MERGEABLE",
            "statusCheckRollup": [],
            "files": [],
        }
    ]
    (pull,) = parse_pull_requests("octocat/example", payload)
    assert pull.author == "dependabot[bot]"
    assert evaluate_pr(pull, trusted=TRUSTED)["decision"] == "auto_merge"


def test_parse_pull_requests_detects_fork_and_files() -> None:
    payload = [
        {
            "number": 7,
            "author": {"login": "octocat"},
            "isDraft": False,
            "headRepositoryOwner": {"login": "someforker"},
            "mergeable": "MERGEABLE",
            "statusCheckRollup": [{"conclusion": "SUCCESS"}],
            "files": [{"path": "a.py"}, {"path": "b.py"}],
        }
    ]
    (pull,) = parse_pull_requests("octocat/example", payload)
    assert pull.is_fork is True
    assert pull.failing_check is False
    assert pull.files == ("a.py", "b.py")


@dataclass
class CannedRunner:
    pr_payload: str
    commands: list[list[str]] = field(default_factory=list)

    def run(
        self,
        command: list[str],
        *,
        cwd: str | Path | None = None,
        input_text: str | None = None,
    ) -> str:
        self.commands.append(command)
        if command[:3] == ["gh", "pr", "list"]:
            return self.pr_payload
        return ""


def _one_clean_pr_payload() -> str:
    return json.dumps(
        [
            {
                "number": 3,
                "author": {"login": "octocat"},
                "isDraft": False,
                "headRepositoryOwner": {"login": "octocat"},
                "mergeable": "MERGEABLE",
                "statusCheckRollup": [{"conclusion": "SUCCESS"}],
                "files": [{"path": "README.md"}],
            }
        ]
    )


def test_dry_run_previews_without_merging() -> None:
    runner = CannedRunner(_one_clean_pr_payload())
    results = automerge_repo(
        "octocat/example",
        trusted=TRUSTED,
        allowlist=set(),
        live=False,
        dry_run=True,
        runner=runner,
    )
    assert results[0]["action"] == "would_enable_auto_merge"
    assert not any(command[:3] == ["gh", "pr", "merge"] for command in runner.commands)


def test_execute_on_allowlisted_repo_enables_auto_merge() -> None:
    runner = CannedRunner(_one_clean_pr_payload())
    results = automerge_repo(
        "octocat/example",
        trusted=TRUSTED,
        allowlist={"octocat/example"},
        live=True,
        dry_run=False,
        runner=runner,
    )
    assert results[0]["action"] == "auto_merge_enabled"
    assert any(
        command[:3] == ["gh", "pr", "merge"] and "--auto" in command
        for command in runner.commands
    )


def test_execute_without_allowlist_is_blocked() -> None:
    runner = CannedRunner(_one_clean_pr_payload())
    results = automerge_repo(
        "octocat/example",
        trusted=TRUSTED,
        allowlist=set(),
        live=True,
        dry_run=False,
        runner=runner,
    )
    assert results[0]["action"] == "blocked_by_live_allowlist"
    assert not any(command[:3] == ["gh", "pr", "merge"] for command in runner.commands)
