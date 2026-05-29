import json
import os
import stat
from pathlib import Path

import pytest

from openai_auth.config import credential_path
from openai_auth.credentials import (
    Credential,
    delete_credentials,
    load_credentials,
    redact_secrets,
    save_credentials,
)


def test_credential_path_defaults_to_project_local_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_AUTH_CREDENTIAL_PATH", raising=False)

    path = credential_path()

    assert path == Path(__file__).resolve().parents[1] / ".openai_auth" / "credentials.json"


def test_credential_path_uses_env_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "custom.json"
    monkeypatch.setenv("OPENAI_AUTH_CREDENTIAL_PATH", str(path))

    assert credential_path() == path


def test_save_load_delete_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    credential = Credential(
        provider="openai-codex",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=1_760_000_000_000,
        account_id="account-123",
        email="person@example.com",
    )

    save_credentials(credential, path)

    assert load_credentials(path) == credential
    delete_credentials(path)
    assert load_credentials(path) is None


def test_save_credentials_sets_file_mode_0600_where_supported(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    credential = Credential(
        provider="openai-codex",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=1_760_000_000_000,
    )

    save_credentials(credential, path)

    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600


def test_load_credentials_rejects_malformed_file(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"provider": "openai-codex"}), encoding="utf-8")

    with pytest.raises(ValueError, match="credential file is invalid"):
        load_credentials(path)


def test_redact_secrets_removes_token_values_from_error_strings() -> None:
    credential = Credential(
        provider="openai-codex",
        access_token="access-secret",
        refresh_token="refresh-secret",
        expires_at=1_760_000_000_000,
    )
    message = "request failed with access-secret and refresh-secret"

    redacted = redact_secrets(message, credential)

    assert "access-secret" not in redacted
    assert "refresh-secret" not in redacted
    assert redacted == "request failed with [REDACTED] and [REDACTED]"
