from __future__ import annotations

from picket.tiers import Tier, classify_finding


def test_patch_and_minor_dependency_updates_are_tier_1() -> None:
    patch = classify_finding({"kind": "dependency", "update_type": "semver-patch"})
    minor = classify_finding({"source": "dependabot", "update_type": "version-update:semver-minor"})

    assert patch.tier is Tier.TIER_1
    assert patch.auto_merge_candidate is True
    assert minor.tier is Tier.TIER_1
    assert minor.auto_merge_candidate is True


def test_major_dependency_update_is_review_only() -> None:
    decision = classify_finding({"kind": "dependency", "update_type": "semver-major"})

    assert decision.tier is Tier.TIER_2
    assert decision.auto_merge_candidate is False


def test_code_scanning_is_tier_2() -> None:
    decision = classify_finding({"kind": "code_scanning", "title": "SQL injection"})

    assert decision.tier is Tier.TIER_2
    assert decision.auto_merge_candidate is False


def test_secret_is_tier_3_and_never_repo_writeable() -> None:
    decision = classify_finding({"kind": "secret_scanning", "secret": True})

    assert decision.tier is Tier.TIER_3
    assert decision.repo_write_allowed is False


def test_auth_and_payment_boundaries_are_tier_3() -> None:
    auth = classify_finding(
        {"kind": "dependency", "update_type": "patch", "file": "src/auth/jwt.py"}
    )
    payment = classify_finding({"kind": "code_scanning", "file": "payments/stripe.py"})

    assert auth.tier is Tier.TIER_3
    assert auth.repo_write_allowed is False
    assert payment.tier is Tier.TIER_3
    assert payment.repo_write_allowed is False


def test_low_risk_config_is_tier_1_but_not_auto_merged() -> None:
    decision = classify_finding({"kind": "config", "low_risk_config": True})

    assert decision.tier is Tier.TIER_1
    assert decision.auto_merge_candidate is False
