#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKPOINT="${PICKET_CHECKPOINT:-$ROOT_DIR/state/checkpoints.json}"
OUTPUT_DIR="${PICKET_DELTA_DIR:-$ROOT_DIR/state/deltas}"
GH_BIN="${GH_BIN:-gh}"
REPO=""
REPO_DIR=""

usage() {
  cat <<'USAGE'
Usage: fetch_delta.sh --repo OWNER/REPO [--repo-dir PATH] [--checkpoint PATH]
                      [--output-dir PATH] [--dry-run]

Fetches only last checkpoint..HEAD diff metadata plus current alert payloads.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO="$2"
      shift 2
      ;;
    --repo-dir)
      REPO_DIR="$2"
      shift 2
      ;;
    --checkpoint)
      CHECKPOINT="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
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
      printf 'fetch_delta.sh: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$REPO" ]]; then
  printf 'fetch_delta.sh: --repo is required\n' >&2
  usage >&2
  exit 2
fi

PY_ARGS=(
  -m picket.delta
  --repo "$REPO"
  --checkpoint "$CHECKPOINT"
  --output-dir "$OUTPUT_DIR"
  --gh-bin "$GH_BIN"
  --dry-run
)

if [[ -n "$REPO_DIR" ]]; then
  PY_ARGS+=(--repo-dir "$REPO_DIR")
fi

cd "$ROOT_DIR"
exec python3 "${PY_ARGS[@]}"

