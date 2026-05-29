from pathlib import Path

from openai_auth.credentials import Credential, save_credentials
from openai_auth.runtime import auth_status


def test_auth_status_reports_not_logged_in(tmp_path: Path) -> None:
    status = auth_status(tmp_path / "missing.json", now_ms=1_700_000_000_000)

    assert status.state == "not_logged_in"
    assert status.account_id is None
    assert status.email is None


def test_auth_status_reports_valid_expired_and_near_expired(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    valid = Credential(
        provider="openai-codex",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=1_700_000_300_001,
        account_id="account-123",
        email="person@example.com",
    )
    save_credentials(valid, path)

    status = auth_status(path, now_ms=1_700_000_000_000)

    assert status.state == "valid"
    assert status.account_id == "account-123"
    assert status.email == "person@example.com"

    save_credentials(
        Credential(
            provider="openai-codex",
            access_token="access-token",
            refresh_token="refresh-token",
            expires_at=1_700_000_299_999,
        ),
        path,
    )

    assert auth_status(path, now_ms=1_700_000_000_000).state == "near_expiry"

    save_credentials(
        Credential(
            provider="openai-codex",
            access_token="access-token",
            refresh_token="refresh-token",
            expires_at=1_700_000_000_000,
        ),
        path,
    )

    assert auth_status(path, now_ms=1_700_000_000_000).state == "expired"
