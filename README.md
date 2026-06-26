# Picket

**Automatic security for every one of your GitHub repos.**
A lightweight, token-frugal bot that watches all your repositories, fixes the
safe things itself, and only ever asks you about the rest.

→ **[See the overview site](https://kiwimaddog2020.github.io/picket/)**

Picket is two layers:

- **Layer 1 — Dependabot, everywhere (native).** One command turns on GitHub's
  built-in vulnerability scanning and auto-fix pull requests across *all* your
  repos. Patch/minor bumps that pass CI merge themselves; bigger ones wait for
  you. Runs in GitHub's cloud, zero upkeep.
- **Layer 2 — the incremental watcher (this repo).** On a schedule it checks only
  the repos that changed since last run (a cheap API call, no AI tokens), reads
  only the new diff, scans it, and tiers what it finds.

## How Layer 2 decides

| Tier | What it is | What Picket does |
|---|---|---|
| 1 | a patch/minor dependency fix | opens a PR and auto-merges it on green CI |
| 2 | a code-scanning finding, or anything ambiguous | opens a PR, labelled for **your** review — never auto-merged |
| 3 | a leaked secret, or auth/payment-touching code | **alerts only** — rotation is your call, never automated |

It ships **dry-run safe**: the live allowlist is empty, so it can't write to any
repo until you add one by hand.

## Quickstart

**Layer 1 (do this first — immediate, no setup):**
```sh
gh repo list YOUR_GITHUB_USERNAME --no-archived --limit 100 --json nameWithOwner \
  -q '.[].nameWithOwner' | while read -r repo; do
  gh api -X PUT "/repos/$repo/vulnerability-alerts" --silent 2>/dev/null \
    && gh api -X PUT "/repos/$repo/automated-security-fixes" --silent 2>/dev/null \
    && echo "  ok  $repo"
done
```

**Layer 2:**
1. Copy `config.example.env` to `~/.config/picket/.env` and fill it in (your
   GitHub username, and the App below).
2. Create a least-privilege **GitHub App** — see [SETUP.md](SETUP.md) for the
   exact permissions — and store its private key outside this repo.
3. Point Picket at your repos and watch a dry run (zero writes):
   ```sh
   gh repo list YOUR_GITHUB_USERNAME --no-archived --limit 100 \
     --json nameWithOwner -q '.[].nameWithOwner' > config/repos.txt
   bin/gh_app_token.py --exec bin/run-once.sh
   ```
4. When you trust it, add **one** repo to `config/live_allowlist.txt` and run
   `bin/run-once.sh --live --execute --write-checkpoint`. Widen it whenever you
   like.

To run it on a schedule, enable the included **[GitHub Action](.github/workflows/picket.yml)**
(it runs a dry-run scan on a cron) or wrap `bin/run-once.sh` in your own cron job.

## Why it's safe by design

- **Costs nothing at rest** — no changed repos means zero AI tokens and zero PRs.
- **Tiered** — only patch/minor dependency bumps on green CI ever auto-merge.
- **Secrets are never auto-fixed** — flagged and escalated, never touched.
- **Its own scoped identity** — Picket acts as a least-privilege GitHub App, not
  your personal token. You see every action and can revoke it in one click.
- **Nothing leaves your GitHub** — Picket runs against the GitHub API and your
  own machine or Actions runner. There is no Picket server.

## Optional extras

Two opt-in add-ons, both off until you set them in `~/.config/picket/.env`:

- **Telegram heads-up.** A phone ping the moment something needs your review (a
  tier-2 PR, or a tier-3 escalation). Create a bot with @BotFather, then set
  `PICKET_TELEGRAM_BOT_TOKEN` and `PICKET_TELEGRAM_CHAT_ID`.
- **Trusted-author auto-merge.** `python3 -m picket.automerge` watches your open
  PRs and enables auto-merge only for authors you trust (set
  `PICKET_TRUSTED_PR_AUTHORS`; `dependabot[bot]` by default), and only when the PR
  is green, conflict-free, not a fork, and touches no secret/auth/payment path.
  Dry-run by default, gated by the same `config/live_allowlist.txt` as everything
  else.

## Requirements

A GitHub account, the [`gh`](https://cli.github.com) CLI, and Python 3.11+.

## Tests

```sh
python3 -m pytest tests -q
ruff check .
```

## License

MIT — see [LICENSE](LICENSE). Built by Kevin Madson.
