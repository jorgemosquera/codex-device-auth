import base64
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from openai_auth.config import credential_path
from openai_auth.errors import CredentialError

SUPPORTED_PROVIDER = "openai-codex"

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
    payload = json.dumps(asdict(credential), indent=2, sort_keys=True)

    if os.name == "posix":
        temp_path: Path | None = None
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            fd, raw_temp_path = tempfile.mkstemp(
                prefix=f".{target_path.name}.",
                suffix=".tmp",
                dir=target_path.parent,
                text=True,
            )
            temp_path = Path(raw_temp_path)
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                file.write(f"{payload}\n")
            temp_path.chmod(0o600)
            temp_path.replace(target_path)
        except OSError:
            cleanup_failed = _delete_temp_file(temp_path)
            message = "credential file could not be saved"
            if cleanup_failed:
                message = "credential file could not be saved; temporary file could not be deleted"
            raise CredentialError(message) from None
        return

    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(f"{payload}\n", encoding="utf-8")
    except OSError:
        raise CredentialError("credential file could not be saved") from None


def load_credentials(path: Path | None = None) -> Credential | None:
    source_path = path or credential_path()
    if not source_path.exists():
        return None

    try:
        data = json.loads(source_path.read_text(encoding="utf-8"))
        return credential_from_mapping(data)
    except (OSError, ValueError):
        raise CredentialError("credential file is invalid") from None


def delete_credentials(path: Path | None = None) -> None:
    target_path = path or credential_path()
    try:
        if target_path.exists():
            target_path.unlink()
    except OSError:
        raise CredentialError("credential file could not be deleted") from None


def _delete_temp_file(temp_path: Path | None) -> bool:
    if temp_path is None:
        return False

    try:
        if temp_path.exists():
            temp_path.unlink()
    except OSError:
        return True

    return False


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

    if not isinstance(provider, str) or provider != SUPPORTED_PROVIDER:
        raise ValueError("credential file is invalid")
    if not isinstance(access_token, str) or not access_token:
        raise ValueError("credential file is invalid")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise ValueError("credential file is invalid")
    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at <= 0:
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


def _decode_jwt_payload(access_token: str) -> dict | None:
    parts = access_token.split(".")
    if len(parts) != 3:
        return None
    try:
        decoded = base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8")
        parsed = json.loads(decoded)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _decode_jwt_identity(access_token: str) -> tuple[str | None, str | None]:
    payload = _decode_jwt_payload(access_token)
    if payload is None:
        return None, None

    account_id: str | None = None
    auth = payload.get("https://api.openai.com/auth")
    if isinstance(auth, dict):
        raw = auth.get("chatgpt_account_id")
        if isinstance(raw, str) and raw:
            account_id = raw

    email: str | None = None
    profile = payload.get("https://api.openai.com/profile")
    if isinstance(profile, dict):
        raw = profile.get("email")
        if isinstance(raw, str) and raw:
            email = raw

    return account_id, email


def _decode_jwt_expiry(access_token: str) -> int | None:
    payload = _decode_jwt_payload(access_token)
    if payload is None:
        return None

    exp = payload.get("exp")
    if isinstance(exp, bool):
        return None
    if not isinstance(exp, (int, float)):
        return None
    if exp <= 0:
        return None

    return int(exp * 1000)


def redact_secrets(message: str, credential: Credential | None = None) -> str:
    redacted = message
    if credential is None:
        return redacted

    secrets = sorted(
        {credential.access_token, credential.refresh_token},
        key=len,
        reverse=True,
    )
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")

    return redacted
