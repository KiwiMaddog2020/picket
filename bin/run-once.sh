#!/usr/bin/env bash
# Picket — one full pass. Finds the repos that changed since last run, scans
# only their new code, and reports. DRY-RUN by default: it writes nothing.
# Pass through apply flags to go live (allowlisted repos only), e.g.:
#   bin/run-once.sh --live --execute --write-checkpoint
#
# Authenticate first so the GitHub API calls work, e.g.:
#   bin/gh_app_token.py --exec bin/run-once.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DELTA_DIR="state/deltas"
rm -rf "$DELTA_DIR"
mkdir -p "$DELTA_DIR" state

CHANGED="$(mktemp)"
trap 'rm -f "$CHANGED"' EXIT
bin/changed_repos.sh --format names > "$CHANGED"

if [ ! -s "$CHANGED" ]; then
  echo "Picket: no changed repos. Nothing to do."
  exit 0
fi

while read -r repo; do
  [ -z "$repo" ] && continue
  echo "Picket: checking $repo"
  bin/fetch_delta.sh --repo "$repo" --output-dir "$DELTA_DIR" || echo "  (skipped $repo)"
done < "$CHANGED"

deltas="$(find "$DELTA_DIR" -name '*.json' -type f)"
if [ -z "$deltas" ]; then
  echo "Picket: no deltas to review."
  exit 0
fi

# shellcheck disable=SC2086  # word-splitting is intentional: one arg per delta file
python3 -m picket.review $deltas > state/review.json
python3 -m picket.apply state/review.json "$@"
echo "Picket: done (dry-run unless you passed --live --execute)."
