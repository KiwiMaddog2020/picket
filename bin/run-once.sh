#!/usr/bin/env bash
# Picket — one full pass. Finds the repos that changed since last run, scans
# only their new code, then checks open PRs for trusted-author auto-merge.
# DRY-RUN by default: it writes nothing. Pass apply flags to go live
# (allowlisted repos only), e.g.:
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

# --- Layer 2 scan: only the repos that changed since last run ---
CHANGED="$(mktemp)"
trap 'rm -f "$CHANGED"' EXIT
bin/changed_repos.sh --format names > "$CHANGED"

if [ -s "$CHANGED" ]; then
  while read -r repo; do
    [ -z "$repo" ] && continue
    echo "Picket: checking $repo"
    bin/fetch_delta.sh --repo "$repo" --output-dir "$DELTA_DIR" || echo "  (skipped $repo)"
  done < "$CHANGED"

  deltas="$(find "$DELTA_DIR" -name '*.json' -type f)"
  if [ -n "$deltas" ]; then
    # shellcheck disable=SC2086  # word-splitting is intentional: one arg per delta file
    python3 -m picket.review $deltas > state/review.json
    python3 -m picket.apply state/review.json "$@"
  else
    echo "Picket: no deltas to review."
  fi
else
  echo "Picket: no changed repos to scan."
fi

# --- Auto-merge pass: trusted-author PRs that are safe. Runs every pass,
# independent of repo changes (dependabot PRs live on side branches). Forwards
# only the flags automerge understands (it keeps no checkpoint) and never fails
# the whole run if the open-PR check is unavailable. ---
am_flags=()
for arg in "$@"; do
  case "$arg" in
    --live | --execute | --dry-run) am_flags+=("$arg") ;;
  esac
done
echo "Picket: checking open PRs for trusted-author auto-merge"
python3 -m picket.automerge ${am_flags[@]+"${am_flags[@]}"} \
  || echo "Picket: auto-merge pass skipped (open-PR check unavailable)"

# --- Orphan-alert pass: patchable Dependabot alerts with no clean PR to
# auto-merge (transitive deps Dependabot won't PR, conflicted PRs, or no PR).
# Escalates the batch loudly on --execute; read-only otherwise. ---
echo "Picket: checking for patchable alerts with no clean PR"
python3 -m picket.orphan_alerts "$@" \
  || echo "Picket: orphan-alert pass skipped (alert check unavailable)"

echo "Picket: done (dry-run unless you passed --live --execute)."
