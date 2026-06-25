# Setting up the Picket GitHub App

Layer 2 acts as a least-privilege **GitHub App** so it never uses your personal
token. This takes about five minutes, once.

## 1. Create the App

Go to **https://github.com/settings/apps/new** and set:

- **Name:** `picket-bot` (or anything you like)
- **Homepage URL:** this repo's URL
- **Webhook:** uncheck **Active** (Picket polls; it needs no webhook)

**Repository permissions** (least privilege — grant only these):

| Permission | Access |
|---|---|
| Contents | Read and write |
| Pull requests | Read and write |
| Dependabot alerts | Read-only |
| Code scanning alerts | Read-only |
| Secret scanning alerts | Read-only |
| Checks | Read-only |
| Metadata | Read-only (mandatory) |

Do **not** grant Administration — Picket must not be able to change repo
settings.

**Where can this GitHub App be installed?** Only on this account.

Create the app.

## 2. Install it and get a key

- On the App's page, **Install App** → choose **All repositories** (or pick the
  repos you want Picket to watch).
- Back on the App's settings, note the numeric **App ID**, then
  **Generate a private key** and download the `.pem`.

## 3. Store the key outside the repo

```sh
mkdir -p ~/.config/picket && chmod 700 ~/.config/picket
mv ~/Downloads/picket-bot.*.private-key.pem ~/.config/picket/app.pem
chmod 600 ~/.config/picket/app.pem
cp config.example.env ~/.config/picket/.env   # then edit it: App ID + your username
```

Never commit the `.pem` or the `.env` — they are gitignored by default.

## 4. (Optional) Run it from GitHub Actions

If you want the scheduled `.github/workflows/picket.yml` to run, add two
repository secrets under **Settings → Secrets and variables → Actions**:

- `PICKET_APP_ID` — the numeric App ID
- `PICKET_APP_KEY` — the full contents of the `.pem`

That's it. Head back to the [README](README.md) quickstart to do a dry run.
