from dataclasses import dataclass
from pathlib import Path

from openai_auth.credentials import Credential, is_expired, is_near_expiry, load_credentials


@dataclass(frozen=True)
class AuthStatus:
    state: str
    account_id: str | None = None
    email: str | None = None


def auth_status(path: Path | None = None, *, now_ms: int) -> AuthStatus:
    credential = load_credentials(path)
    if credential is None:
        return AuthStatus(state="not_logged_in")

    state = _credential_state(credential, now_ms)
    return AuthStatus(
        state=state,
        account_id=credential.account_id,
        email=credential.email,
    )


def _credential_state(credential: Credential, now_ms: int) -> str:
    if is_expired(credential, now_ms=now_ms):
        return "expired"
    if is_near_expiry(credential, now_ms=now_ms):
        return "near_expiry"

    return "valid"
