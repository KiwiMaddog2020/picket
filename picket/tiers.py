from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Tier(str, Enum):
    TIER_1 = "tier-1"
    TIER_2 = "tier-2"
    TIER_3 = "tier-3"


@dataclass(frozen=True)
class TierDecision:
    tier: Tier
    reason: str
    auto_merge_candidate: bool = False
    repo_write_allowed: bool = True


DEPENDENCY_KINDS = {"dependency", "dependabot", "dependency_update"}
CODE_SCANNING_KINDS = {"code_scanning", "static_analysis", "sast"}
SECRET_KINDS = {"secret", "secret_scanning", "credential"}
PATCH_MINOR = {"patch", "minor", "semver-patch", "semver-minor"}
MAJOR = {"major", "semver-major"}
AUTH_MARKERS = (
    "auth",
    "oauth",
    "login",
    "jwt",
    "session",
    "permission",
    "credential",
    "token",
)
PAYMENT_MARKERS = ("payment", "billing", "stripe", "checkout", "invoice")
SECRET_MARKERS = ("secret", "password", "private key", "api key", "credential")


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _combined_text(finding: Mapping[str, Any]) -> str:
    parts = [
        finding.get("kind"),
        finding.get("source"),
        finding.get("title"),
        finding.get("message"),
        finding.get("file"),
        finding.get("path"),
        finding.get("evidence"),
    ]
    tags = finding.get("tags", [])
    if isinstance(tags, list):
        parts.extend(tags)
    return " ".join(_lower(part) for part in parts)


def normalize_update_type(value: Any) -> str:
    text = _lower(value).replace("version-update:", "").replace("_", "-")
    if text in PATCH_MINOR or text in MAJOR:
        return text.replace("semver-", "")
    if text.endswith("semver-patch"):
        return "patch"
    if text.endswith("semver-minor"):
        return "minor"
    if text.endswith("semver-major"):
        return "major"
    return text


def touches_auth_or_payment(finding: Mapping[str, Any]) -> str | None:
    if finding.get("touches_auth"):
        return "auth"
    if finding.get("touches_payment"):
        return "payment"

    path_text = _lower(finding.get("file") or finding.get("path"))
    if any(marker in path_text for marker in AUTH_MARKERS):
        return "auth"
    if any(marker in path_text for marker in PAYMENT_MARKERS):
        return "payment"
    return None


def is_secret_finding(finding: Mapping[str, Any]) -> bool:
    if finding.get("secret") is True:
        return True
    kind = _lower(finding.get("kind"))
    if kind in SECRET_KINDS:
        return True
    text = _combined_text(finding)
    return any(marker in text for marker in SECRET_MARKERS)


def classify_finding(finding: Mapping[str, Any]) -> TierDecision:
    if is_secret_finding(finding):
        return TierDecision(
            tier=Tier.TIER_3,
            reason="secret or credential finding; escalation only",
            repo_write_allowed=False,
        )

    sensitive_boundary = touches_auth_or_payment(finding)
    if sensitive_boundary:
        return TierDecision(
            tier=Tier.TIER_3,
            reason=f"{sensitive_boundary}-touching change; escalation only",
            repo_write_allowed=False,
        )

    kind = _lower(finding.get("kind"))
    source = _lower(finding.get("source"))
    if kind in DEPENDENCY_KINDS or source == "dependabot":
        update_type = normalize_update_type(finding.get("update_type"))
        if update_type in {"patch", "minor"}:
            return TierDecision(
                tier=Tier.TIER_1,
                reason="patch/minor dependency update",
                auto_merge_candidate=True,
            )
        return TierDecision(
            tier=Tier.TIER_2,
            reason="dependency update is major or unknown",
            auto_merge_candidate=False,
        )

    if kind in CODE_SCANNING_KINDS or source == "code_scanning":
        return TierDecision(tier=Tier.TIER_2, reason="code-scanning finding needs review")

    if finding.get("low_risk_config") is True:
        return TierDecision(
            tier=Tier.TIER_1,
            reason="clearly scoped low-risk config finding; PR only, no auto-merge",
            auto_merge_candidate=False,
        )

    return TierDecision(tier=Tier.TIER_2, reason="ambiguous security finding needs review")


def annotate_finding(finding: Mapping[str, Any]) -> dict[str, Any]:
    decision = classify_finding(finding)
    annotated = dict(finding)
    annotated["tier"] = decision.tier.value
    annotated["tier_reason"] = decision.reason
    annotated["auto_merge_candidate"] = decision.auto_merge_candidate
    annotated["repo_write_allowed"] = decision.repo_write_allowed
    return annotated
