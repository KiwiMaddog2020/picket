from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from picket.tiers import normalize_update_type

SECRET_LINE = re.compile(
    r"(?i)(api[_-]?key|access[_-]?token|secret|password|private[_-]?key)"
    r"[A-Z0-9_-]*\s*[:=]\s*['\"][^'\"]{8,}"
)
DANGEROUS_LINE = re.compile(r"(?i)(eval\(|exec\(|shell\s*=\s*true|pickle\.loads)")
SEMVER = re.compile(r"(?P<name>[A-Za-z0-9_.-]+).{0,8}v?(?P<version>\d+\.\d+\.\d+)")


@dataclass(frozen=True)
class AddedLine:
    file: str
    line_number: int | None
    text: str


def _classify_version_change(before: str, after: str) -> str:
    before_parts = [int(part) for part in before.split(".")[:3]]
    after_parts = [int(part) for part in after.split(".")[:3]]
    if after_parts[0] != before_parts[0]:
        return "major"
    if after_parts[1] != before_parts[1]:
        return "minor"
    if after_parts[2] != before_parts[2]:
        return "patch"
    return "unknown"


def _is_dependency_path(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name in {
        "requirements.txt",
        "package.json",
        "package-lock.json",
        "poetry.lock",
        "pyproject.toml",
        "cargo.toml",
        "cargo.lock",
        "go.mod",
        "go.sum",
        "gemfile",
        "gemfile.lock",
    }


def iter_added_lines(patch: str) -> list[AddedLine]:
    current_file = ""
    new_line: int | None = None
    added: list[AddedLine] = []

    for raw in patch.splitlines():
        if raw.startswith("+++ b/"):
            current_file = raw.removeprefix("+++ b/")
            new_line = None
            continue
        if raw.startswith("@@"):
            match = re.search(r"\+(\d+)", raw)
            new_line = int(match.group(1)) if match else None
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            added.append(AddedLine(file=current_file, line_number=new_line, text=raw[1:]))
            if new_line is not None:
                new_line += 1
            continue
        if not raw.startswith("-") and new_line is not None:
            new_line += 1
    return added


def dependency_findings_from_patch(repo: str, patch: str) -> list[dict[str, Any]]:
    removals: dict[tuple[str, str], str] = {}
    findings: list[dict[str, Any]] = []
    current_file = ""

    for raw in patch.splitlines():
        if raw.startswith("--- a/"):
            current_file = raw.removeprefix("--- a/")
            continue
        if raw.startswith("+++ b/"):
            current_file = raw.removeprefix("+++ b/")
            continue
        if not current_file or not _is_dependency_path(current_file):
            continue
        if not raw.startswith(("-", "+")) or raw.startswith(("---", "+++")):
            continue

        match = SEMVER.search(raw[1:])
        if not match:
            continue
        key = (current_file, match.group("name").lower())
        version = match.group("version")
        if raw.startswith("-"):
            removals[key] = version
        elif raw.startswith("+") and key in removals:
            update_type = normalize_update_type(_classify_version_change(removals[key], version))
            findings.append(
                {
                    "repo": repo,
                    "source": "sec-scan",
                    "kind": "dependency",
                    "file": current_file,
                    "title": f"{match.group('name')} dependency bump",
                    "package": match.group("name"),
                    "from_version": removals[key],
                    "to_version": version,
                    "update_type": update_type,
                    "evidence": raw[1:].strip(),
                }
            )
    return findings


def code_findings_from_patch(repo: str, patch: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for added in iter_added_lines(patch):
        if SECRET_LINE.search(added.text):
            findings.append(
                {
                    "repo": repo,
                    "source": "sec-scan",
                    "kind": "secret",
                    "file": added.file,
                    "line": added.line_number,
                    "title": "Potential secret introduced in diff",
                    "secret": True,
                    "evidence": added.text.strip(),
                }
            )
        elif DANGEROUS_LINE.search(added.text):
            findings.append(
                {
                    "repo": repo,
                    "source": "sec-scan",
                    "kind": "code_scanning",
                    "file": added.file,
                    "line": added.line_number,
                    "title": "Potential unsafe code pattern introduced in diff",
                    "evidence": added.text.strip(),
                }
            )
    return findings


def findings_from_alert_payloads(
    repo: str,
    alerts: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for alert in alerts.get("secret_scanning", []):
        findings.append(
            {
                "repo": repo,
                "source": "secret_scanning",
                "kind": "secret_scanning",
                "title": alert.get("secret_type_display_name") or "Secret scanning alert",
                "secret": True,
                "evidence": alert.get("html_url") or alert.get("secret_type"),
            }
        )
    for alert in alerts.get("code_scanning", []):
        rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}
        findings.append(
            {
                "repo": repo,
                "source": "code_scanning",
                "kind": "code_scanning",
                "title": rule.get("description") or rule.get("id") or "Code scanning alert",
                "severity": rule.get("severity") or rule.get("security_severity_level"),
                "evidence": alert.get("html_url"),
            }
        )
    for alert in alerts.get("dependabot", []):
        vulnerability = alert.get("security_vulnerability", {})
        package = vulnerability.get("package", {}) if isinstance(vulnerability, dict) else {}
        first_patched = vulnerability.get("first_patched_version", {})
        update_type = alert.get("update_type") or alert.get("dependency_update_type") or "unknown"
        findings.append(
            {
                "repo": repo,
                "source": "dependabot",
                "kind": "dependabot",
                "title": alert.get("security_advisory", {}).get("summary")
                if isinstance(alert.get("security_advisory"), dict)
                else "Dependabot alert",
                "package": package.get("name") if isinstance(package, dict) else None,
                "patched_version": first_patched.get("identifier")
                if isinstance(first_patched, dict)
                else None,
                "update_type": normalize_update_type(update_type),
                "evidence": alert.get("html_url"),
            }
        )
    return findings


def scan_delta(
    repo: str,
    patch: str,
    alerts: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    return [
        *dependency_findings_from_patch(repo, patch),
        *code_findings_from_patch(repo, patch),
        *findings_from_alert_payloads(repo, alerts),
    ]
