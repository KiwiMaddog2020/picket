from __future__ import annotations

import datetime

from picket import audit_ledger as al

NOW = datetime.datetime(2026, 6, 27, 12, tzinfo=datetime.timezone.utc).timestamp()
FRESH = "2026-06-26T12:00:00Z"  # 1 day before NOW
STALE = "2026-03-01T12:00:00Z"  # > 90 days before NOW


def _rec(*, streak: int, input_hash: str = "h1", last_audited: str = FRESH) -> dict:
    return {"input_hash": input_hash, "clean_streak": streak, "last_audited": last_audited}


def test_dimension_due_baseline_until_two_clean() -> None:
    assert al.dimension_due(_rec(streak=0), "h1", NOW)[1] == "baseline"
    assert al.dimension_due(_rec(streak=1), "h1", NOW)[1] == "baseline"
    assert al.dimension_due(_rec(streak=2), "h1", NOW)[0] is False


def test_dimension_due_on_input_change() -> None:
    due, reason = al.dimension_due(_rec(streak=2, input_hash="old"), "new", NOW)
    assert due is True
    assert reason == "changed"


def test_dimension_due_on_staleness() -> None:
    due, reason = al.dimension_due(_rec(streak=2, last_audited=STALE), "h1", NOW)
    assert due is True
    assert reason == "stale"


def test_dimension_clean_when_baseline_met_unchanged_fresh() -> None:
    assert al.dimension_due(_rec(streak=2), "h1", NOW) == (False, "clean")


def test_record_audit_streak_transitions() -> None:
    ledger = al.empty_ledger()
    ledger = al.record_audit(ledger, "o/r", "deps", input_hash="h1", findings=[], now=FRESH)
    assert al._dimension_record(ledger, "o/r", "deps")["clean_streak"] == 1
    # clean again, same inputs -> baseline grows
    ledger = al.record_audit(ledger, "o/r", "deps", input_hash="h1", findings=[], now=FRESH)
    assert al._dimension_record(ledger, "o/r", "deps")["clean_streak"] == 2
    # inputs change, clean -> fresh baseline at 1
    ledger = al.record_audit(ledger, "o/r", "deps", input_hash="h2", findings=[], now=FRESH)
    assert al._dimension_record(ledger, "o/r", "deps")["clean_streak"] == 1
    # findings -> reset to 0
    ledger = al.record_audit(
        ledger, "o/r", "deps", input_hash="h2", findings=[{"title": "x"}], now=FRESH
    )
    assert al._dimension_record(ledger, "o/r", "deps")["clean_streak"] == 0


def test_due_set_filters_and_risk_orders() -> None:
    ledger = al.empty_ledger()
    # quiet/established repo: all four dims clean baseline-met + fresh + matching hash
    for dim in al.DIMENSIONS:
        ledger = al.record_audit(
            ledger, "o/quiet", dim, input_hash=f"{dim}-h", findings=[], now=FRESH
        )
        ledger = al.record_audit(
            ledger, "o/quiet", dim, input_hash=f"{dim}-h", findings=[], now=FRESH
        )
    ledger["repos"]["o/quiet"]["risk"] = {"public": False, "prior_findings": 0}
    ledger["repos"]["o/loud"] = {"risk": {"public": True, "prior_findings": 3}}

    hashes = {
        "o/quiet": {d: f"{d}-h" for d in al.DIMENSIONS},  # unchanged -> not due
        "o/loud": {d: "anything" for d in al.DIMENSIONS},  # new repo -> due
    }
    due = al.due_set(ledger, hashes, NOW)
    repos = [item["repo"] for item in due]
    assert repos == ["o/loud"]  # quiet is fully clean, filtered out


def test_sprint_take_covers_all_by_last_sprint() -> None:
    assert al.sprint_take(10, 1) == 3  # ceil(10/4)
    assert al.sprint_take(7, 2) == 3  # ceil(7/3)
    assert al.sprint_take(4, 3) == 2  # ceil(4/2)
    assert al.sprint_take(2, 4) == 2  # ceil(2/1) -> all remaining
    assert al.sprint_take(9, 4) == 9  # last sprint always clears the backlog


def test_sprint_index_for_day() -> None:
    assert al.sprint_index_for_day(1) == 1
    assert al.sprint_index_for_day(7) == 1
    assert al.sprint_index_for_day(8) == 2
    assert al.sprint_index_for_day(21) == 3
    assert al.sprint_index_for_day(28) == 4
    assert al.sprint_index_for_day(31) == 4  # 5th week folds onto the last sprint


def test_age_days_parses_and_tolerates_garbage() -> None:
    assert al._age_days(STALE, NOW) > 90
    assert al._age_days(None, NOW) == float("inf")
    assert al._age_days("not-a-date", NOW) == float("inf")
