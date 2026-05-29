import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from openai_auth.config import credential_path

NEAR_EXPIRY_WINDOW_MS = 300_000


@dataclass(frozen=True)
class Credential:
    provider: str
    access_token: str
    refresh_token: str
    expires_at: int
    account_id: str | None = None
    email: str | None = None


def save_credentials(credential: Credential, path: Path | None = None) -> None:
    target_path = path or credential_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(asdict(credential), indent=2, sort_keys=True)
    target_path.write_text(f"{payload}\n", encoding="utf-8")

    if os.name == "posix":
        target_path.chmod(0o600)


def load_credentials(path: Path | None = None) -> Credential | None:
    source_path = path or credential_path()
    if not source_path.exists():
        return None

    data = json.loads(source_path.read_text(encoding="utf-8"))
    return credential_from_mapping(data)


def delete_credentials(path: Path | None = None) -> None:
    target_path = path or credential_path()
    if target_path.exists():
        target_path.unlink()


def is_expired(credential: Credential, *, now_ms: int) -> bool:
    return credential.expires_at <= now_ms


def is_near_expiry(
    credential: Credential,
    *,
    now_ms: int,
    window_ms: int = NEAR_EXPIRY_WINDOW_MS,
) -> bool:
    if window_ms <= 0:
        raise ValueError("window_ms must be positive")

    return credential.expires_at <= now_ms + window_ms


def credential_from_mapping(data: Any) -> Credential:
    if not isinstance(data, dict):
        raise ValueError("credential file is invalid")

    provider = data.get("provider")
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    expires_at = data.get("expires_at")
    account_id = data.get("account_id")
    email = data.get("email")

    if not isinstance(provider, str) or not provider:
        raise ValueError("credential file is invalid")
    if not isinstance(access_token, str) or not access_token:
        raise ValueError("credential file is invalid")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise ValueError("credential file is invalid")
    if not isinstance(expires_at, int) or expires_at <= 0:
        raise ValueError("credential file is invalid")
    if account_id is not None and not isinstance(account_id, str):
        raise ValueError("credential file is invalid")
    if email is not None and not isinstance(email, str):
        raise ValueError("credential file is invalid")

    return Credential(
        provider=provider,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        account_id=account_id,
        email=email,
    )


def redact_secrets(message: str, credential: Credential | None = None) -> str:
    redacted = message
    if credential is None:
        return redacted

    for token in (credential.access_token, credential.refresh_token):
        if token:
            redacted = redacted.replace(token, "[REDACTED]")

    return redacted
