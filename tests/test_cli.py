from pathlib import Path

import pytest

from openai_auth.cli import main
from openai_auth.credentials import Credential, save_credentials
from openai_auth.errors import RuntimeRequestError
from openai_auth.runtime import RuntimeTestResult


def test_status_reports_logged_out(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["status", "--credential-path", str(tmp_path / "missing.json")])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == "not logged in\n"


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


def test_cli_error_output_redacts_token_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_run_test_request(*_args: object, **_kwargs: object) -> RuntimeTestResult:
        raise RuntimeRequestError("failed with access-secret and refresh-secret")

    monkeypatch.setattr("openai_auth.cli.run_test_request", fake_run_test_request)

    exit_code = main(["test"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "failed with [REDACTED] and [REDACTED]" in captured.err
    assert_no_secret(captured.err)


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

    monkeypatch.setattr("openai_auth.cli.login_with_device_code", fake_login)
    monkeypatch.setattr("openai_auth.cli.refresh_credential", fake_refresh)
    monkeypatch.setattr("openai_auth.cli.run_test_request", fake_test)

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
