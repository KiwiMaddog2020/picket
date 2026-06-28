"""Per-dimension content hashes for a repo, from the GitHub git-tree (no clone).

One `git/trees/{sha}?recursive=1` call yields every tracked path with its blob
SHA. A dimension's input hash is a stable hash over just the (path, blob_sha) pairs
whose path belongs to that dimension. The blob SHA changes iff the file content
changes, so the hash moves exactly when that dimension's inputs move. A docs-only
commit moves nothing expensive; a dep bump moves only `deps`; a new route moves
`sast` and `config`.

The `secret` dimension keys on HEAD instead: history only grows, so any new commit
should re-trigger a full-history secret scan.
"""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath

from picket.prefilter import GhClient

DEP_FILENAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "pyproject.toml",
    "cargo.toml",
    "cargo.lock",
    "go.mod",
    "go.sum",
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
}
SAST_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".sh",
    ".rb",
    ".java",
    ".php",
    ".c",
    ".cpp",
    ".cs",
}
CONFIG_FILENAMES = {
    ".env.example",
    ".env.sample",
    "wrangler.toml",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "_headers",
    "_redirects",
    "netlify.toml",
    "vercel.json",
}
CONFIG_PATH_MARKERS = (".github/workflows/",)


def _is_dep(path: str) -> bool:
    return PurePosixPath(path).name.lower() in DEP_FILENAMES


def _is_sast(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in SAST_EXTENSIONS


def _is_config(path: str) -> bool:
    low = path.lower()
    name = PurePosixPath(path).name.lower()
    return (
        name in CONFIG_FILENAMES
        or low.endswith(".env")
        or any(marker in low for marker in CONFIG_PATH_MARKERS)
    )


# Dimensions whose hash is derived from the file tree (secret is HEAD-based).
TREE_PREDICATES = {"deps": _is_dep, "sast": _is_sast, "config": _is_config}


def _hash_pairs(pairs: list[tuple[str, str]]) -> str:
    """Order-independent stable digest over (path, blob_sha) pairs."""
    digest = hashlib.sha256()
    for path, blob_sha in sorted(pairs):
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(blob_sha.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()[:16]


def tree_entries(client: GhClient, repo: str, head_sha: str) -> list[tuple[str, str]]:
    """All (path, blob_sha) for tracked files at head_sha, via one git-tree call."""
    owner, name = repo.split("/", 1)
    data = client.run_json(["api", f"/repos/{owner}/{name}/git/trees/{head_sha}?recursive=1"])
    if not isinstance(data, dict):
        return []
    entries: list[tuple[str, str]] = []
    for entry in data.get("tree", []) or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == "blob" and entry.get("path") and entry.get("sha"):
            entries.append((str(entry["path"]), str(entry["sha"])))
    return entries


def dimension_hashes(
    entries: list[tuple[str, str]],
    head_sha: str,
    commit_count: int | None = None,
) -> dict[str, str]:
    """The four per-dimension input hashes for a repo."""
    hashes = {
        dimension: _hash_pairs([(p, s) for p, s in entries if predicate(p)])
        for dimension, predicate in TREE_PREDICATES.items()
    }
    # History only grows: any new commit (HEAD move) should re-scan secrets.
    hashes["secret"] = f"{head_sha or ''}:{commit_count if commit_count is not None else ''}"
    return hashes


def repo_input_hashes(
    client: GhClient,
    repo: str,
    head_sha: str,
    commit_count: int | None = None,
) -> dict[str, str]:
    """Fetch the tree and return the four per-dimension input hashes for `repo`."""
    entries = tree_entries(client, repo, head_sha)
    return dimension_hashes(entries, head_sha, commit_count)
