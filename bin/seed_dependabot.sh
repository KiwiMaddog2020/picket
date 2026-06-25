#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="${PICKET_DEPENDABOT_TEMPLATE:-$ROOT_DIR/templates/dependabot.yml}"
REPO_DIR=""
WRITE=0
FORCE=0

usage() {
  cat <<'USAGE'
Usage: seed_dependabot.sh --repo-dir PATH [--write] [--force]

Dry-run is the default. With --write, copies templates/dependabot.yml into
PATH/.github/dependabot.yml only when the target lacks one, unless --force is set.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-dir)
      REPO_DIR="$2"
      shift 2
      ;;
    --write)
      WRITE=1
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'seed_dependabot.sh: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$REPO_DIR" ]]; then
  printf 'seed_dependabot.sh: --repo-dir is required\n' >&2
  usage >&2
  exit 2
fi

TARGET="$REPO_DIR/.github/dependabot.yml"
if [[ -f "$TARGET" && "$FORCE" -ne 1 ]]; then
  printf '{"action":"skip","reason":"exists","target":"%s"}\n' "$TARGET"
  exit 0
fi

if [[ "$WRITE" -ne 1 ]]; then
  printf '{"action":"would_seed","target":"%s"}\n' "$TARGET"
  exit 0
fi

mkdir -p "$(dirname "$TARGET")"
cp "$TEMPLATE" "$TARGET"
printf '{"action":"seeded","target":"%s"}\n' "$TARGET"

