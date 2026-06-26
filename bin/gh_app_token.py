#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from base64 import urlsafe_b64encode
from pathlib import Path
from typing import Any


def base64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_rs256(signing_input: str, key_path: Path, openssl_bin: str = "openssl") -> str:
    completed = subprocess.run(
        [openssl_bin, "dgst", "-sha256", "-sign", str(key_path), "-binary"],
        input=signing_input.encode("ascii"),
        check=True,
        capture_output=True,
    )
    return base64url(completed.stdout)


def build_jwt(app_id: str, key_path: Path, *, now: int | None = None) -> str:
    issued_at = int(time.time() if now is None else now) - 60
    payload = {
        "iat": issued_at,
        "exp": issued_at + 600,
        "iss": app_id,
    }
    header = {"alg": "RS256", "typ": "JWT"}
    signing_input = ".".join(
        [
            base64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            base64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        ]
    )
    return f"{signing_input}.{sign_rs256(signing_input, key_path)}"


def gh_api_json(args: list[str], *, token: str, gh_bin: str = "gh") -> Any:
    # App-JWT calls require `Authorization: Bearer <jwt>`. `gh api` sends
    # `Authorization: token <jwt>`, which GitHub rejects for App JWTs
    # ("a JSON web token could not be decoded"), so these go through curl with
    # an explicit Bearer header. (gh_bin is unused here but kept for call-site
    # compatibility; the resulting installation token works with gh normally.)
    path = args[0]
    method = args[args.index("-X") + 1] if "-X" in args else "GET"
    completed = subprocess.run(
        [
            "curl",
            "-fsS",
            "-X",
            method,
            "-H",
            f"Authorization: Bearer {token}",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            f"https://api.github.com{path}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    if not completed.stdout.strip():
        return None
    return json.loads(completed.stdout)


def resolve_installation_id(
    *,
    app_jwt: str,
    explicit_installation_id: str | None,
    owner: str | None,
    gh_bin: str,
) -> str:
    if explicit_installation_id:
        return explicit_installation_id

    installations = gh_api_json(["/app/installations"], token=app_jwt, gh_bin=gh_bin)
    if not isinstance(installations, list):
        raise RuntimeError("GitHub returned a non-list installation response")

    if owner:
        for installation in installations:
            account = installation.get("account", {}) if isinstance(installation, dict) else {}
            if account.get("login") == owner:
                return str(installation["id"])
        raise RuntimeError(f"no GitHub App installation found for owner {owner}")

    if len(installations) == 1 and isinstance(installations[0], dict):
        return str(installations[0]["id"])
    raise RuntimeError("set PICKET_APP_INSTALLATION_ID when multiple installations exist")


def mint_installation_token(
    *,
    app_id: str,
    key_path: Path,
    installation_id: str | None,
    owner: str | None,
    gh_bin: str,
) -> dict[str, Any]:
    app_jwt = build_jwt(app_id, key_path)
    resolved_installation_id = resolve_installation_id(
        app_jwt=app_jwt,
        explicit_installation_id=installation_id,
        owner=owner,
        gh_bin=gh_bin,
    )
    response = gh_api_json(
        [f"/app/installations/{resolved_installation_id}/access_tokens", "-X", "POST"],
        token=app_jwt,
        gh_bin=gh_bin,
    )
    if not isinstance(response, dict) or not response.get("token"):
        raise RuntimeError("GitHub did not return an installation token")
    return {
        "token": str(response["token"]),
        "installation_id": resolved_installation_id,
        "expires_at": response.get("expires_at"),
    }


def env_value(primary: str, fallback: str | None = None) -> str | None:
    return os.environ.get(primary) or (os.environ.get(fallback) if fallback else None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mint a per-run GitHub App installation token and exec a command."
    )
    parser.add_argument("--app-id", default=env_value("PICKET_APP_ID", "APP_ID"))
    parser.add_argument("--key", default=env_value("PICKET_APP_KEY"))
    parser.add_argument("--installation-id", default=env_value("PICKET_APP_INSTALLATION_ID"))
    parser.add_argument("--owner", default=env_value("PICKET_OWNER"))
    parser.add_argument("--gh-bin", default=os.environ.get("GH_BIN", "gh"))
    parser.add_argument("--exec", dest="exec_command", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.app_id:
        raise SystemExit("PICKET_APP_ID or APP_ID is required")
    if not args.key:
        raise SystemExit("PICKET_APP_KEY is required")

    key_path = Path(args.key).expanduser()
    if not key_path.exists():
        raise SystemExit(f"GitHub App key path does not exist: {key_path}")

    minted = mint_installation_token(
        app_id=str(args.app_id),
        key_path=key_path,
        installation_id=args.installation_id,
        owner=args.owner,
        gh_bin=args.gh_bin,
    )

    if args.exec_command:
        env = os.environ.copy()
        env["GH_TOKEN"] = minted["token"]
        os.execvpe(args.exec_command[0], args.exec_command, env)

    json.dump(
        {
            "installation_id": minted["installation_id"],
            "expires_at": minted["expires_at"],
            "token_minted": True,
        },
        sys.stdout,
        indent=2,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

