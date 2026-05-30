import base64
import json
import os
import stat
from pathlib import Path

import pytest

from openai_auth.config import credential_path
from openai_auth.credentials import (
    Credential,
    decode_jwt_expiry,
    decode_jwt_identity,
    delete_credentials,
    is_expired,
    is_near_expiry,
    load_credentials,
    redact_secrets,
    save_credentials,
)
from openai_auth.errors import CredentialError


def _make_jwt(payload: dict) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"header.{encoded}.sig"


def test_credential_path_defaults_to_project_local_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_AUTH_CREDENTIAL_PATH", raising=False)

    path = credential_path()

    assert path == Path(__file__).resolve().parents[1] / ".openai_auth" / "credentials.json"


def test_credential_path_uses_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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


def test_save_credentials_does_not_write_to_preexisting_temp_file(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    temp_path = tmp_path / ".credentials.json.tmp"
    temp_path.write_text("existing", encoding="utf-8")
    temp_path.chmod(0o666)
    credential = Credential(
        provider="openai-codex",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=1_760_000_000_000,
    )

    save_credentials(credential, path)

    assert temp_path.read_text(encoding="utf-8") == "existing"
    assert "access-token" not in temp_path.read_text(encoding="utf-8")


def test_save_credentials_wraps_directory_creation_failure(tmp_path: Path) -> None:
    blocking_file = tmp_path / "blocked"
    blocking_file.write_text("not a directory", encoding="utf-8")
    credential = Credential(
        provider="openai-codex",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=1_760_000_000_000,
    )

    with pytest.raises(CredentialError, match="credential file could not be saved"):
        save_credentials(credential, blocking_file / "credentials.json")


def test_save_credentials_cleanup_failure_still_raises_credential_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "credentials.json"
    credential = Credential(
        provider="openai-codex",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=1_760_000_000_000,
    )
    original_replace = Path.replace
    original_unlink = Path.unlink

    def fake_replace(source_path: Path, target_path: Path) -> Path:
        if target_path == path:
            raise OSError("replace failed")
        return original_replace(source_path, target_path)

    def fake_unlink(current_path: Path) -> None:
        if current_path.name.startswith(".credentials.json."):
            raise OSError("cleanup failed")
        original_unlink(current_path)

    monkeypatch.setattr(Path, "replace", fake_replace)
    monkeypatch.setattr(Path, "unlink", fake_unlink)

    with pytest.raises(CredentialError, match="credential file could not be saved"):
        save_credentials(credential, path)


def test_delete_credentials_wraps_unlink_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "credentials.json"
    path.write_text("{}", encoding="utf-8")

    original_unlink = Path.unlink

    def fake_unlink(current_path: Path) -> None:
        if current_path != path:
            original_unlink(current_path)
            return
        raise OSError("cannot unlink")

    monkeypatch.setattr(Path, "unlink", fake_unlink)

    with pytest.raises(CredentialError, match="credential file could not be deleted"):
        delete_credentials(path)


def test_load_credentials_rejects_malformed_file(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"provider": "openai-codex"}), encoding="utf-8")

    with pytest.raises(CredentialError, match="credential file is invalid"):
        load_credentials(path)


def test_load_credentials_rejects_boolean_expiry(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    path.write_text(
        json.dumps(
            {
                "provider": "openai-codex",
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "expires_at": True,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(CredentialError, match="credential file is invalid"):
        load_credentials(path)


def test_load_credentials_rejects_unsupported_provider(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    path.write_text(
        json.dumps(
            {
                "provider": "other-provider",
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "expires_at": 1_760_000_000_000,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(CredentialError, match="credential file is invalid"):
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


def test_redact_secrets_handles_overlapping_token_values() -> None:
    credential = Credential(
        provider="openai-codex",
        access_token="access-abc",
        refresh_token="access-abcdef",
        expires_at=1_760_000_000_000,
    )

    redacted = redact_secrets("failed with access-abcdef", credential)

    assert redacted == "failed with [REDACTED]"
    assert "def" not in redacted


def test_redact_secrets_handles_partially_overlapping_token_values() -> None:
    credential = Credential(
        provider="openai-codex",
        access_token="abcXYZ",
        refresh_token="XYZdef",
        expires_at=1_760_000_000_000,
    )

    redacted = redact_secrets("failed with abcXYZdef", credential)

    assert redacted == "failed with [REDACTED]"
    assert "abc" not in redacted
    assert "def" not in redacted


def test_load_credentials_normalizes_empty_metadata(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    path.write_text(
        json.dumps(
            {
                "provider": "openai-codex",
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "expires_at": 1_760_000_000_000,
                "account_id": "",
                "email": "",
            }
        ),
        encoding="utf-8",
    )

    credential = load_credentials(path)

    assert credential is not None
    assert credential.account_id is None
    assert credential.email is None


def test_expiry_helpers_detect_expired_and_near_expiry_credentials() -> None:
    expired = Credential(
        provider="openai-codex",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=1_700_000_000_000,
    )
    near_expiry = Credential(
        provider="openai-codex",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=1_700_000_299_999,
    )
    valid = Credential(
        provider="openai-codex",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=1_700_000_300_001,
    )

    assert is_expired(expired, now_ms=1_700_000_000_000)
    assert not is_expired(valid, now_ms=1_700_000_000_000)
    assert is_near_expiry(near_expiry, now_ms=1_700_000_000_000)
    assert not is_near_expiry(valid, now_ms=1_700_000_000_000)


def test_decode_jwt_identity_extracts_account_id_and_email() -> None:
    token = _make_jwt(
        {
            "https://api.openai.com/auth": {"chatgpt_account_id": "acct-123"},
            "https://api.openai.com/profile": {"email": "user@example.com"},
        }
    )

    account_id, email = decode_jwt_identity(token)

    assert account_id == "acct-123"
    assert email == "user@example.com"


def test_decode_jwt_identity_returns_none_for_absent_claims() -> None:
    token = _make_jwt({})

    account_id, email = decode_jwt_identity(token)

    assert account_id is None
    assert email is None


def test_decode_jwt_identity_returns_none_for_malformed_token() -> None:
    assert decode_jwt_identity("nodots") == (None, None)
    assert decode_jwt_identity("a.b") == (None, None)
    assert decode_jwt_identity("a.!!!.c") == (None, None)


def test_decode_jwt_expiry_converts_exp_to_milliseconds() -> None:
    token = _make_jwt({"exp": 1_700_000_000})

    assert decode_jwt_expiry(token) == 1_700_000_000_000


def test_decode_jwt_expiry_returns_none_for_missing_or_invalid_exp() -> None:
    assert decode_jwt_expiry(_make_jwt({})) is None
    assert decode_jwt_expiry(_make_jwt({"exp": 0})) is None
    assert decode_jwt_expiry(_make_jwt({"exp": True})) is None
    assert decode_jwt_expiry(_make_jwt({"exp": "1700000000"})) is None
