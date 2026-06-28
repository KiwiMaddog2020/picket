"""Turn audit findings into proposed fixes, tiered by how much autonomy is safe.

Policy (Kevin's locked choice: tiered auto-apply, single-model drafting):
- dependency findings        -> DEFER  (the auto-merge + orphan layer already owns them)
- repo-setting findings      -> ESCALATE (scanning off, branch protection: not a code patch)
- secret findings            -> DRAFT_PR (strip to an env ref) + ALWAYS escalate "rotate it"
- Tier-1 auto-merge-eligible -> AUTO_MERGE_PR (PR + self-merge on green CI)
- everything else with a file -> DRAFT_PR (Claude drafts, you approve)
- anything not fixable as a file -> ESCALATE

Drafting is single-model: Claude drafts a unified diff, then a second Claude call
self-checks it PASS/FAIL; a non-PASS falls back to escalation rather than a PR.

Shadow mode computes every proposal but executes nothing, so the first full cycle
shows exactly what it WOULD do across 46 repos before anything merges. The live
executor clones the one repo and reuses the existing, tested create_pr_for_finding
(branch -> apply -> push -> gh pr create -> optional auto-merge); the bot never
reads, rotates, or enters a live credential.
"""

from __future__ import annotations

import base64
import binascii
import json
import shutil
import subprocess
import tempfile
from typing import Any, Callable

from picket.apply import Runner, SubprocessRunner, create_pr_for_finding
from picket.tiers import DEPENDENCY_KINDS, Tier, annotate_finding, is_secret_finding

AUTO_MERGE_PR = "auto_merge_pr"
DRAFT_PR = "draft_pr"
ESCALATE = "escalate"
DEFER = "defer"


def _gh_safe(client: Any, path: str) -> Any | None:
    try:
        return client.run_json(["api", path])
    except (subprocess.CalledProcessError, json.JSONDecodeError, ValueError):
        return None


def _summary(finding: dict[str, Any], action: str) -> str:
    repo = finding.get("repo", "?")
    where = finding.get("file") or finding.get("setting") or finding.get("kind") or "finding"
    return f"[{action}] {repo}: {finding.get('title', where)}"


def plan_fix(finding: dict[str, Any]) -> dict[str, Any]:
    """Pure policy: decide the action for one finding. No I/O."""
    annotated = annotate_finding(finding)
    tier = annotated["tier"]
    setting = annotated.get("setting")
    kind = str(annotated.get("kind", "")).lower()
    source = str(annotated.get("source", "")).lower()
    secret = is_secret_finding(annotated)
    fixable = bool(annotated.get("file")) and not setting

    if (kind in DEPENDENCY_KINDS or source == "dependabot") and not secret:
        action = DEFER
    elif setting:
        action = ESCALATE
    elif secret:
        action = DRAFT_PR if fixable else ESCALATE
    elif not fixable:
        action = ESCALATE
    elif tier == Tier.TIER_1.value and annotated.get("auto_merge_candidate"):
        action = AUTO_MERGE_PR
    else:
        action = DRAFT_PR

    return {
        "action": action,
        "tier": tier,
        "requires_rotation": secret,
        "fixable": fixable,
        "summary": _summary(annotated, action),
        "finding": annotated,
    }


# --- drafting (single model) ----------------------------------------------

def build_draft_prompt(finding: dict[str, Any], content: str) -> str:
    return (
        "You are a security fix bot. Output ONLY a unified diff that `git apply` accepts. "
        "No prose, no code fences.\n"
        f"Repo: {finding.get('repo')}\nFile: {finding.get('file')}\n"
        f"Issue: {finding.get('title')}\nEvidence: {finding.get('evidence')}\n"
        "--- current file content ---\n"
        f"{content}\n"
        "--- end ---\n"
        "Produce the minimal diff that fixes the issue. For a hardcoded secret, replace the "
        "literal with an environment-variable lookup and NEVER invent a real value."
    )


def looks_like_diff(text: str) -> bool:
    return bool(text) and "@@" in text and ("+++ " in text or "diff --git" in text)


def extract_diff(text: str) -> str:
    """Pull a diff out of a model reply, tolerating accidental ``` fencing."""
    if "```" in text:
        blocks = text.split("```")
        for block in blocks:
            body = block[block.find("\n") + 1 :] if block[:6] in ("diff\n", "patch\n") else block
            if looks_like_diff(body):
                return body.strip()
    return text.strip()


def _run_text(runner: Runner, cmd: list[str]) -> str | None:
    try:
        return runner.run(cmd)
    except (subprocess.CalledProcessError, OSError):
        return None


def claude_drafter(
    finding: dict[str, Any], content: str, *, runner: Runner, model: str | None = None
) -> str | None:
    cmd = ["claude", "-p", build_draft_prompt(finding, content), "--output-format", "text"]
    if model:
        cmd += ["--model", model]
    out = _run_text(runner, cmd)
    if not out:
        return None
    diff = extract_diff(out)
    return diff if looks_like_diff(diff) else None


def claude_self_check(
    finding: dict[str, Any], patch: str, *, runner: Runner, model: str | None = None
) -> bool:
    prompt = (
        "Does this unified diff fully and safely fix the issue with no unintended side effects? "
        "Answer PASS or FAIL with one short reason.\n"
        f"Issue: {finding.get('title')}\nDiff:\n{patch}"
    )
    cmd = ["claude", "-p", prompt, "--output-format", "text"]
    if model:
        cmd += ["--model", model]
    out = _run_text(runner, cmd)
    return bool(out) and out.strip().upper().startswith("PASS")


# --- content + live execution ---------------------------------------------

def fetch_file_content(client: Any, repo: str, path: str, head_sha: str | None = None) -> str:
    ref = f"?ref={head_sha}" if head_sha else ""
    data = _gh_safe(client, f"/repos/{repo}/contents/{path}{ref}")
    if isinstance(data, dict) and data.get("encoding") == "base64":
        try:
            return base64.b64decode(data.get("content", "")).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return ""
    return ""


def clone_and_pr(
    finding: dict[str, Any],
    patch: str,
    *,
    tier: str,
    auto_merge: bool,
    runner: Runner,
    head_sha: str | None = None,
) -> dict[str, Any]:
    """LIVE: shallow-clone the one repo and reuse create_pr_for_finding to open the PR."""
    repo = str(finding["repo"])
    tmp = tempfile.mkdtemp(prefix="secbot-fix-")
    try:
        runner.run(["gh", "repo", "clone", repo, tmp, "--", "--depth", "1"])
        review = {"repo": repo, "repo_dir": tmp, "head_sha": head_sha or ""}
        fix_finding = dict(finding)
        fix_finding["fix_patch"] = patch
        fix_finding["auto_merge_candidate"] = bool(auto_merge)
        return create_pr_for_finding(
            review=review, finding=fix_finding, tier=Tier(tier), runner=runner
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- the orchestrator ------------------------------------------------------

def propose_fixes(
    findings: list[dict[str, Any]],
    *,
    client: Any,
    runner: Runner | None = None,
    head_sha: str | None = None,
    drafter: Callable[..., str | None] = claude_drafter,
    self_checker: Callable[..., bool] = claude_self_check,
    executor: Callable[..., dict[str, Any]] = clone_and_pr,
    shadow: bool = True,
) -> dict[str, Any]:
    """Plan (and, when not shadow, apply) a fix per finding. Returns a report."""
    runner = runner or SubprocessRunner()
    report: dict[str, list[dict[str, Any]]] = {
        "proposed": [],
        "escalations": [],
        "deferred": [],
        "rotations": [],
    }
    for finding in findings:
        plan = plan_fix(finding)
        if plan["requires_rotation"]:
            report["rotations"].append(plan)  # always surface "rotate this credential"

        action = plan["action"]
        if action == DEFER:
            report["deferred"].append(plan)
            continue
        if action == ESCALATE:
            report["escalations"].append(plan)
            continue

        annotated = plan["finding"]
        content = fetch_file_content(client, annotated["repo"], annotated["file"], head_sha)
        patch = drafter(annotated, content, runner=runner)
        if not patch or not self_checker(annotated, patch, runner=runner):
            plan["reason"] = "draft_unavailable_or_self_check_failed"
            report["escalations"].append(plan)  # fall back to telling Kevin
            continue

        plan["patch"] = patch
        if not shadow:
            plan["result"] = executor(
                annotated,
                patch,
                tier=plan["tier"],
                auto_merge=(action == AUTO_MERGE_PR),
                runner=runner,
                head_sha=head_sha,
            )
        report["proposed"].append(plan)
    return report
