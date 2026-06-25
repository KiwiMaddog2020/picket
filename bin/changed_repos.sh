#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKPOINT="${PICKET_CHECKPOINT:-$ROOT_DIR/state/checkpoints.json}"
REPOS_FILE="${PICKET_REPOS_FILE:-$ROOT_DIR/config/repos.txt}"
OWNER="${PICKET_OWNER:-}"
FORMAT="json"
GH_BIN="${GH_BIN:-gh}"
REPOS=()

usage() {
  cat <<'USAGE'
Usage: changed_repos.sh [--checkpoint PATH] [--repos-file PATH] [--owner OWNER]
                        [--repo OWNER/REPO] [--format json|names] [--dry-run]

Dry-run is the default. The script only reports changed repos; it never writes.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --checkpoint)
      CHECKPOINT="$2"
      shift 2
      ;;
    --repos-file)
      REPOS_FILE="$2"
      shift 2
      ;;
    --owner)
      OWNER="$2"
      shift 2
      ;;
    --repo)
      REPOS+=("$2")
      shift 2
      ;;
    --format)
      FORMAT="$2"
      shift 2
      ;;
    --dry-run)
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'changed_repos.sh: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

PY_ARGS=(
  -m picket.prefilter
  --checkpoint "$CHECKPOINT"
  --repos-file "$REPOS_FILE"
  --owner "$OWNER"
  --format "$FORMAT"
  --gh-bin "$GH_BIN"
  --dry-run
)

for repo in "${REPOS[@]}"; do
  PY_ARGS+=(--repo "$repo")
done

cd "$ROOT_DIR"
exec python3 "${PY_ARGS[@]}"

