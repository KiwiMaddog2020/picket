#!/usr/bin/env bash
# Picket — one rolling deep-audit sprint (1 of 4 Sundays per month).
#
# SHADOW by default: it deep-audits this sprint's risk-ordered slice of the DUE
# set, proposes fixes, and sends a digest, but merges nothing. Pass --go-live to
# actually open/merge the fix PRs once you have reviewed a shadow run.
#
# Everything stays gated: only repos in config/live_allowlist.txt are touched,
# and the per-dimension ledger means quiet repos cost a single tree call.
#
# Authenticate first (mints the GitHub App token), e.g.:
#   bin/gh_app_token.py --exec bin/audit-sprint.sh --shadow
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
mkdir -p state

echo "Picket: audit sprint starting ($(date))"
python3 -m picket.audit_sprint "$@"
echo "Picket: audit sprint done (shadow unless you passed --go-live)."
