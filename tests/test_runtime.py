from hashlib import sha256
from pathlib import Path

import httpx
import pytest

from openai_auth.credentials import Credential, save_credentials
from openai_auth.errors import CredentialError, RuntimeRequestError
from openai_auth.cli import main
from openai_auth.runtime import RuntimeTestResult, auth_status, build_auth_headers, run_test_request


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


def test_build_auth_headers_include_bearer_and_account_id() -> None:
    credential = Credential(
        provider="openai-codex",
        access_token="access-secret",
        refresh_token="refresh-secret",
        expires_at=1_700_000_300_001,
        account_id="account-123",
    )

    headers = build_auth_headers(credential)

    assert_bearer_matches(headers["Authorization"], credential.access_token)
    assert headers["OpenAI-Account"] == "account-123"


def test_header_failure_output_does_not_expose_token_values() -> None:
    credential = Credential(
        provider="openai-codex",
        access_token="access-secret",
        refresh_token="refresh-secret",
        expires_at=1_700_000_300_001,
    )

    sanitized = repr(sanitized_headers_for_assertion(credential))

    assert_secret_absent(sanitized, credential)


def sanitized_headers_for_assertion(credential: Credential) -> dict[str, str]:
    headers = build_auth_headers(credential)
    return {**headers, "Authorization": "[REDACTED]"}


def secret_digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def assert_bearer_matches(authorization: str, expected_token: str) -> None:
    if not authorization.startswith("Bearer "):
        raise AssertionError("authorization header missing bearer prefix")

    actual_digest = secret_digest(authorization.removeprefix("Bearer "))
    expected_digest = secret_digest(expected_token)
    if actual_digest != expected_digest:
        raise AssertionError("authorization bearer token mismatch")


def assert_secret_absent(value: str, credential: Credential) -> None:
    for secret in (credential.access_token, credential.refresh_token):
        if secret in value:
            raise AssertionError("secret was exposed")


def test_run_test_request_refreshes_expired_credentials_before_request(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    new_access_token = "new-access"
    save_credentials(
        Credential(
            provider="openai-codex",
            access_token="old-access",
            refresh_token="old-refresh",
            expires_at=1_700_000_000_000,
            account_id="account-123",
        ),
        path,
    )
    seen_token_digests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth/token":
            return httpx.Response(
                200,
                json={
                    "access_token": new_access_token,
                    "expires_in": 1800,
                },
            )

        header = request.headers["Authorization"]
        assert_bearer_matches(header, new_access_token)
        seen_token_digests.append(secret_digest(header.removeprefix("Bearer ")))
        return httpx.Response(200, json={"ok": True})

    result = run_test_request(
        httpx.Client(transport=httpx.MockTransport(handler)),
        path=path,
        now_ms=lambda: 1_700_000_000_000,
        request_timeout=2,
    )

    assert result.ok
    assert seen_token_digests == [secret_digest(new_access_token)]


def test_run_test_request_returns_success_for_mocked_http(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    credential = Credential(
        provider="openai-codex",
        access_token="access-secret",
        refresh_token="refresh-secret",
        expires_at=1_700_000_300_001,
    )
    save_credentials(credential, path)

    def handler(request: httpx.Request) -> httpx.Response:
        assert_bearer_matches(request.headers["Authorization"], credential.access_token)
        return httpx.Response(200, json={"ok": True})

    result = run_test_request(
        httpx.Client(transport=httpx.MockTransport(handler)),
        path=path,
        now_ms=lambda: 1_700_000_000_000,
        request_timeout=2,
    )

    assert result.ok
    assert result.status_code == 200


def test_run_test_request_rejection_is_sanitized(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    credential = Credential(
        provider="openai-codex",
        access_token="access-secret",
        refresh_token="refresh-secret",
        expires_at=1_700_000_300_001,
    )
    save_credentials(credential, path)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "bad access-secret"})

    with pytest.raises(RuntimeRequestError) as exc_info:
        run_test_request(
            httpx.Client(transport=httpx.MockTransport(handler)),
            path=path,
            now_ms=lambda: 1_700_000_000_000,
            request_timeout=2,
        )

    message = str(exc_info.value)
    assert "runtime request rejected with HTTP 401" in message
    assert_secret_absent(message, credential)


def test_run_test_request_rejection_uses_concise_safe_error_detail(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    credential = Credential(
        provider="openai-codex",
        access_token="access-secret",
        refresh_token="refresh-secret",
        expires_at=1_700_000_300_001,
    )
    save_credentials(credential, path)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "error": {
                    "message": "denied",
                    "sensitive": "unrelated-secret",
                }
            },
        )

    with pytest.raises(RuntimeRequestError) as exc_info:
        run_test_request(
            httpx.Client(transport=httpx.MockTransport(handler)),
            path=path,
            now_ms=lambda: 1_700_000_000_000,
            request_timeout=2,
        )

    message = str(exc_info.value)
    assert "denied" in message
    assert "unrelated-secret" not in message


def test_run_test_request_rejection_uses_generic_non_json_detail(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    credential = Credential(
        provider="openai-codex",
        access_token="access-secret",
        refresh_token="refresh-secret",
        expires_at=1_700_000_300_001,
    )
    save_credentials(credential, path)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="upstream access-secret unrelated-secret")

    with pytest.raises(RuntimeRequestError) as exc_info:
        run_test_request(
            httpx.Client(transport=httpx.MockTransport(handler)),
            path=path,
            now_ms=lambda: 1_700_000_000_000,
            request_timeout=2,
        )

    message = str(exc_info.value)
    assert "runtime request rejected with HTTP 500: request rejected" in message
    assert "unrelated-secret" not in message


def test_run_test_request_refresh_save_failure_is_sanitized(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "credentials.json"
    credential = Credential(
        provider="openai-codex",
        access_token="old-access",
        refresh_token="old-refresh",
        expires_at=1_700_000_000_000,
    )
    save_credentials(credential, path)

    def fake_save(*_args: object, **_kwargs: object) -> None:
        raise CredentialError("old-access old-refresh")

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"access_token": "new-access", "expires_in": 1800})

    monkeypatch.setattr("openai_auth.runtime.save_credentials", fake_save)

    with pytest.raises(RuntimeRequestError) as exc_info:
        run_test_request(
            httpx.Client(transport=httpx.MockTransport(handler)),
            path=path,
            now_ms=lambda: 1_700_000_000_000,
            request_timeout=2,
        )

    message = str(exc_info.value)
    assert "credential file could not be saved" in message
    assert_secret_absent(message, credential)


def test_module_entrypoint_dispatches_test_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_run_test_request(
        _client: httpx.Client,
        *,
        path: Path | None = None,
        now_ms: object,
        request_timeout: float = 10,
    ) -> RuntimeTestResult:
        return RuntimeTestResult(ok=True, status_code=204)

    monkeypatch.setattr("openai_auth.cli.run_test_request", fake_run_test_request)

    exit_code = main(["test", "--credential-path", str(tmp_path / "credentials.json")])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == "authenticated request succeeded: HTTP 204\n"
