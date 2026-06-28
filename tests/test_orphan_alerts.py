from __future__ import annotations

import datetime

from picket import orphan_alerts as oa
from picket.automerge import PullRequest

# A fixed UTC instant so the age gate never depends on the runner's timezone.
NOW = datetime.datetime(2026, 6, 27, 12, tzinfo=datetime.timezone.utc).timestamp()


def _alert(
    *,
    package: str = "vite",
    patched: str | None = "8.0.16",
    created_at: str = "2026-06-25T12:00:00Z",  # 48h before NOW
    number: int = 1,
    severity: str = "high",
) -> dict:
    return {
        "number": number,
        "created_at": created_at,
        "html_url": f"https://github.com/o/r/security/dependabot/{number}",
        "security_vulnerability": {
            "package": {"name": package},
            "first_patched_version": {"identifier": patched} if patched else None,
            "severity": severity,
        },
        "dependency": {"manifest_path": "package-lock.json"},
    }


def _pr(
    *, title: str = "chore(deps): bump vite from 8.0.14 to 8.1.0", merge_state: str = "CLEAN",
    is_draft: bool = False,
) -> PullRequest:
    return PullRequest(
        repo="o/r", number=9, author="dependabot[bot]", is_draft=is_draft,
        is_fork=False, merge_state=merge_state, title=title,
    )


def test_orphaned_when_patchable_aged_and_no_pr() -> None:
    out = oa.orphaned_patchable_alerts([_alert()], [], NOW)
    assert len(out) == 1
    assert out[0]["package"] == "vite"
    assert out[0]["reason"] == "no_pr"


def test_covered_by_clean_pr_is_not_orphaned() -> None:
    assert oa.orphaned_patchable_alerts([_alert()], [_pr(merge_state="CLEAN")], NOW) == []


def test_dirty_pr_still_orphaned_with_distinct_reason() -> None:
    prs = [_pr(title="bump vite and friends", merge_state="DIRTY")]
    out = oa.orphaned_patchable_alerts([_alert()], prs, NOW)
    assert len(out) == 1
    assert out[0]["reason"] == "dirty_or_blocked_pr"


def test_too_fresh_is_skipped() -> None:
    fresh = _alert(created_at="2026-06-27T06:00:00Z")  # 6h before NOW
    assert oa.orphaned_patchable_alerts([fresh], [], NOW, min_age_hours=24) == []


def test_not_patchable_is_skipped() -> None:
    assert oa.orphaned_patchable_alerts([_alert(patched=None)], [], NOW) == []


def test_render_orphan_summary_is_plain_text() -> None:
    orphans = [
        {
            "repo": "o/palette", "package": "vite", "patched_version": "6.4.3",
            "severity": "high", "reason": "dirty_or_blocked_pr",
        }
    ]
    text = oa.render_orphan_summary(orphans)
    assert "palette" in text
    assert "vite -> 6.4.3" in text
    assert "PR conflicted" in text
    assert "<" not in text  # plain text, no HTML
