from collections.abc import Sequence
import argparse
from pathlib import Path
import re
import sys
import time

import httpx

from codex_device_auth.credentials import (
    Credential,
    delete_credentials,
    is_expired,
    is_near_expiry,
    load_credentials,
    redact_secrets,
    save_credentials,
)
from codex_device_auth.device_code import login_with_device_code, refresh_credential
from codex_device_auth.errors import AuthError, CredentialError
from codex_device_auth.runtime import run_test_request


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    credential_path = _credential_path_arg(args.credential_path)

    if args.command == "login":
        return _login_command(credential_path)
    if args.command == "status":
        return _status_command(credential_path)
    if args.command == "refresh":
        return _refresh_command(credential_path)
    if args.command == "test":
        return _test_command(credential_path)
    if args.command == "logout":
        return _logout_command(credential_path)

    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m codex_device_auth")
    parser.add_argument(
        "command",
        choices=["login", "status", "refresh", "test", "logout"],
    )
    parser.add_argument("--credential-path")
    return parser


def _credential_path_arg(value: str | None) -> Path | None:
    if value is None:
        return None

    return Path(value)


def _login_command(path: Path | None) -> int:
    with httpx.Client() as client:
        try:
            credential = login_with_device_code(client)
            save_credentials(credential, path)
        except AuthError as exc:
            print(_redacted_error(exc), file=sys.stderr)
            return 1

    print("logged in")
    return 0


def _status_command(path: Path | None) -> int:
    try:
        credential = load_credentials(path)
    except CredentialError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if credential is None:
        print("not logged in")
        return 0

    parts = [_status_state(credential)]
    if credential.account_id is not None:
        parts.append(f"account={credential.account_id}")
    if credential.email is not None:
        parts.append(f"email={credential.email}")

    print(redact_secrets(" ".join(parts), credential))
    return 0


def _refresh_command(path: Path | None) -> int:
    try:
        credential = load_credentials(path)
    except CredentialError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if credential is None:
        print("not logged in", file=sys.stderr)
        return 1

    with httpx.Client() as client:
        try:
            refreshed = refresh_credential(client, credential, now_ms=_now_ms)
            save_credentials(refreshed, path)
        except AuthError as exc:
            print(_redacted_error(exc, credential), file=sys.stderr)
            return 1

    print("refreshed")
    return 0


def _test_command(path: Path | None) -> int:
    try:
        credential = load_credentials(path)
    except CredentialError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    with httpx.Client() as client:
        try:
            result = run_test_request(client, path=path, now_ms=_now_ms)
        except CredentialError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except AuthError as exc:
            print(_redacted_error(exc, credential), file=sys.stderr)
            return 1

    print(f"authenticated codex request succeeded: {result.response_text!r}")
    return 0


def _logout_command(path: Path | None) -> int:
    try:
        delete_credentials(path)
    except CredentialError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print("logged out")
    return 0


def _redacted_error(exc: AuthError, credential: Credential | None = None) -> str:
    message = redact_secrets(str(exc), credential)
    return re.sub(r"\b(?:access|refresh)-[A-Za-z0-9._-]+\b", "[REDACTED]", message)


def _status_state(credential: Credential) -> str:
    now_ms = _now_ms()
    if is_expired(credential, now_ms=now_ms):
        return "expired"
    if is_near_expiry(credential, now_ms=now_ms):
        return "near_expiry"

    return "valid"


def _now_ms() -> int:
    return int(time.time() * 1000)
