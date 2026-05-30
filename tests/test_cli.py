from pathlib import Path

import pytest

from codex_device_auth.cli import main
from codex_device_auth.credentials import Credential, save_credentials
from codex_device_auth.errors import CredentialError, RuntimeRequestError
from codex_device_auth.runtime import RuntimeTestResult


def test_status_reports_logged_out(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["status", "--credential-path", str(tmp_path / "missing.json")])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == "not logged in\n"


def test_status_reports_malformed_credentials_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "credentials.json"
    path.write_text("{invalid", encoding="utf-8")

    exit_code = main(["status", "--credential-path", str(path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == "credential file is invalid\n"


def test_refresh_reports_malformed_credentials_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "credentials.json"
    path.write_text("{invalid", encoding="utf-8")

    exit_code = main(["refresh", "--credential-path", str(path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == "credential file is invalid\n"


def test_test_reports_malformed_credentials_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "credentials.json"
    path.write_text("{invalid", encoding="utf-8")

    exit_code = main(["test", "--credential-path", str(path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == "credential file is invalid\n"


def test_status_reports_logged_in_without_tokens(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "credentials.json"
    save_credentials(
        Credential(
            provider="openai-codex",
            access_token="access-secret",
            refresh_token="refresh-secret",
            expires_at=4_102_444_800_000,
            account_id="account-123",
            email="person@example.com",
        ),
        path,
    )

    exit_code = main(["status", "--credential-path", str(path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "valid" in captured.out
    assert "account-123" in captured.out
    assert "person@example.com" in captured.out
    assert_no_secret(captured.out)


def test_status_redacts_tokens_from_metadata(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "credentials.json"
    save_credentials(
        Credential(
            provider="openai-codex",
            access_token="access-secret",
            refresh_token="refresh-secret",
            expires_at=4_102_444_800_000,
            account_id="access-secret",
            email="refresh-secret",
        ),
        path,
    )

    exit_code = main(["status", "--credential-path", str(path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "account=[REDACTED]" in captured.out
    assert "email=[REDACTED]" in captured.out
    assert_no_secret(captured.out)


def test_logout_deletes_credentials(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "credentials.json"
    save_credentials(
        Credential(
            provider="openai-codex",
            access_token="access-secret",
            refresh_token="refresh-secret",
            expires_at=4_102_444_800_000,
        ),
        path,
    )

    exit_code = main(["logout", "--credential-path", str(path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == "logged out\n"
    assert not path.exists()


def test_logout_reports_delete_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_delete(*_args: object, **_kwargs: object) -> None:
        raise CredentialError("credential file could not be deleted")

    monkeypatch.setattr("codex_device_auth.cli.delete_credentials", fake_delete)

    exit_code = main(["logout"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == "credential file could not be deleted\n"


def test_cli_error_output_redacts_token_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_run_test_request(*_args: object, **_kwargs: object) -> RuntimeTestResult:
        raise RuntimeRequestError("failed with access-secret and refresh-secret")

    monkeypatch.setattr("codex_device_auth.cli.run_test_request", fake_run_test_request)

    exit_code = main(["test", "--credential-path", str(tmp_path / "credentials.json")])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "failed with [REDACTED] and [REDACTED]" in captured.err
    assert_no_secret(captured.err)


def test_cli_error_output_redacts_loaded_credential_tokens(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "credentials.json"
    save_credentials(
        Credential(
            provider="openai-codex",
            access_token="access-secret",
            refresh_token="refresh-secret",
            expires_at=4_102_444_800_000,
        ),
        path,
    )

    def fake_run_test_request(*_args: object, **_kwargs: object) -> RuntimeTestResult:
        raise RuntimeRequestError("failed with access-secret and refresh-secret")

    monkeypatch.setattr("codex_device_auth.cli.run_test_request", fake_run_test_request)

    exit_code = main(["test", "--credential-path", str(path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == "failed with [REDACTED] and [REDACTED]\n"


def test_login_reports_credential_save_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    credential = Credential(
        provider="openai-codex",
        access_token="access-secret",
        refresh_token="refresh-secret",
        expires_at=4_102_444_800_000,
    )

    def fake_login(*_args: object, **_kwargs: object) -> Credential:
        return credential

    def fake_save(*_args: object, **_kwargs: object) -> None:
        raise CredentialError("credential file could not be saved")

    monkeypatch.setattr("codex_device_auth.cli.login_with_device_code", fake_login)
    monkeypatch.setattr("codex_device_auth.cli.save_credentials", fake_save)

    exit_code = main(["login", "--credential-path", str(tmp_path / "credentials.json")])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == "credential file could not be saved\n"


def test_dispatch_calls_login_refresh_and_runtime_test(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []
    path = tmp_path / "credentials.json"
    credential = Credential(
        provider="openai-codex",
        access_token="access-secret",
        refresh_token="refresh-secret",
        expires_at=4_102_444_800_000,
    )
    save_credentials(credential, path)

    def fake_login(*_args: object, **_kwargs: object) -> Credential:
        calls.append("login")
        return credential

    def fake_refresh(*_args: object, **_kwargs: object) -> Credential:
        calls.append("refresh")
        return credential

    def fake_test(*_args: object, **_kwargs: object) -> RuntimeTestResult:
        calls.append("test")
        return RuntimeTestResult(ok=True, status_code=204)

    monkeypatch.setattr("codex_device_auth.cli.login_with_device_code", fake_login)
    monkeypatch.setattr("codex_device_auth.cli.refresh_credential", fake_refresh)
    monkeypatch.setattr("codex_device_auth.cli.run_test_request", fake_test)

    assert main(["login", "--credential-path", str(path)]) == 0
    assert main(["refresh", "--credential-path", str(path)]) == 0
    assert main(["test", "--credential-path", str(path)]) == 0

    captured = capsys.readouterr()
    assert calls == ["login", "refresh", "test"]
    assert_no_secret(captured.out)


def assert_no_secret(value: str) -> None:
    for secret in ("access-secret", "refresh-secret"):
        if secret in value:
            raise AssertionError("secret was exposed")
