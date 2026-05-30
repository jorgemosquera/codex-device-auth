import base64
import json as _json
import urllib.parse
from collections.abc import Callable

import httpx
import pytest

from openai_auth.config import CODEX_CLIENT_ID, DEVICE_CALLBACK_URL
from openai_auth.credentials import Credential
from openai_auth.device_code import login_with_device_code, refresh_credential
from openai_auth.errors import (
    DeviceCodeNetworkError,
    DeviceCodeResponseError,
    DeviceCodeTimeoutError,
    RefreshTokenError,
)


def make_jwt(
    account_id: str | None = None, email: str | None = None, exp: int | None = None
) -> str:
    payload: dict = {}
    if account_id is not None:
        payload["https://api.openai.com/auth"] = {"chatgpt_account_id": account_id}
    if email is not None:
        payload["https://api.openai.com/profile"] = {"email": email}
    if exp is not None:
        payload["exp"] = exp
    encoded = base64.urlsafe_b64encode(_json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"header.{encoded}.sig"


def make_client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_login_with_device_code_returns_credentials_after_token_exchange() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={
                    "device_auth_id": "device-123",
                    "user_code": "ABCD-EFGH",
                    "interval": 5,
                },
            )
        if len(requests) == 2:
            return httpx.Response(403)
        if len(requests) == 3:
            return httpx.Response(
                200,
                json={"authorization_code": "auth-123", "code_verifier": "verifier-abc"},
            )
        body = urllib.parse.parse_qs(request.content.decode())
        assert body["grant_type"] == ["authorization_code"]
        assert body["code"] == ["auth-123"]
        assert body["code_verifier"] == ["verifier-abc"]
        assert body["client_id"] == [CODEX_CLIENT_ID]
        assert body["redirect_uri"] == [DEVICE_CALLBACK_URL]
        return httpx.Response(
            200,
            json={
                "access_token": make_jwt(account_id="account-123", email="person@example.com"),
                "refresh_token": "refresh-123",
                "expires_in": 3600,
            },
        )

    messages: list[str] = []

    credential = login_with_device_code(
        make_client(handler),
        output=messages.append,
        now_ms=lambda: 1_700_000_000_000,
        sleep=lambda _seconds: None,
        max_poll_seconds=30,
        request_timeout=2,
    )

    assert credential == Credential(
        provider="openai-codex",
        access_token=make_jwt(account_id="account-123", email="person@example.com"),
        refresh_token="refresh-123",
        expires_at=1_700_003_600_000,
        account_id="account-123",
        email="person@example.com",
    )
    assert messages == ["Visit https://auth.openai.com/codex/device and enter code ABCD-EFGH"]
    assert [request.url.path for request in requests] == [
        "/api/accounts/deviceauth/usercode",
        "/api/accounts/deviceauth/token",
        "/api/accounts/deviceauth/token",
        "/oauth/token",
    ]


def test_login_with_device_code_times_out_after_bounded_polling() -> None:
    request_count = 0
    current_ms = 1_700_000_000_000

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        if request_count == 1:
            return httpx.Response(
                200,
                json={
                    "device_auth_id": "device-123",
                    "user_code": "ABCD-EFGH",
                    "interval": 5,
                },
            )
        return httpx.Response(403)

    def now_ms() -> int:
        return current_ms

    def sleep(seconds: float) -> None:
        nonlocal current_ms
        current_ms += int(seconds * 1000)

    with pytest.raises(DeviceCodeTimeoutError, match="device code login timed out"):
        login_with_device_code(
            make_client(handler),
            output=lambda _message: None,
            now_ms=now_ms,
            sleep=sleep,
            max_poll_seconds=10,
            poll_interval_seconds=5,
            request_timeout=2,
        )

    assert request_count == 3


def test_login_with_device_code_raises_for_unexpected_poll_status() -> None:
    request_count = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        if request_count == 1:
            return httpx.Response(
                200,
                json={
                    "device_auth_id": "device-123",
                    "user_code": "ABCD-EFGH",
                    "interval": 5,
                },
            )
        return httpx.Response(400)

    with pytest.raises(DeviceCodeNetworkError):
        login_with_device_code(
            make_client(handler),
            output=lambda _message: None,
            now_ms=lambda: 1_700_000_000_000,
            sleep=lambda _seconds: None,
            max_poll_seconds=30,
            request_timeout=2,
        )


def test_login_with_device_code_raises_sanitized_error_for_malformed_token_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/deviceauth/usercode"):
            return httpx.Response(
                200,
                json={
                    "device_auth_id": "device-123",
                    "user_code": "ABCD-EFGH",
                    "interval": 5,
                },
            )
        if request.url.path.endswith("/deviceauth/token"):
            return httpx.Response(
                200,
                json={"authorization_code": "auth-123", "code_verifier": "verifier-abc"},
            )
        return httpx.Response(200, json={"access_token": "leaked-access", "expires_in": 3600})

    with pytest.raises(DeviceCodeResponseError) as exc_info:
        login_with_device_code(
            make_client(handler),
            output=lambda _message: None,
            now_ms=lambda: 1_700_000_000_000,
            sleep=lambda _seconds: None,
            max_poll_seconds=30,
            request_timeout=2,
        )

    message = str(exc_info.value)
    assert "token response is invalid" in message
    assert "leaked-access" not in message


def test_login_with_device_code_rejects_boolean_expiry() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/deviceauth/usercode"):
            return httpx.Response(
                200,
                json={
                    "device_auth_id": "device-123",
                    "user_code": "ABCD-EFGH",
                    "interval": 5,
                },
            )
        if request.url.path.endswith("/deviceauth/token"):
            return httpx.Response(
                200,
                json={"authorization_code": "auth-123", "code_verifier": "verifier-abc"},
            )
        return httpx.Response(
            200,
            json={
                "access_token": make_jwt(),
                "refresh_token": "refresh-token",
                "expires_in": True,
            },
        )

    with pytest.raises(DeviceCodeResponseError, match="token response is invalid"):
        login_with_device_code(
            make_client(handler),
            output=lambda _message: None,
            now_ms=lambda: 1_700_000_000_000,
            sleep=lambda _seconds: None,
            max_poll_seconds=30,
            request_timeout=2,
        )


def test_refresh_credential_replaces_access_token_and_expiry() -> None:
    credential = Credential(
        provider="openai-codex",
        access_token="old-access",
        refresh_token="refresh-token",
        expires_at=1_700_000_000_000,
        account_id="account-123",
        email="person@example.com",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/oauth/token"
        body = urllib.parse.parse_qs(request.content.decode())
        assert body["grant_type"] == ["refresh_token"]
        assert body["client_id"] == [CODEX_CLIENT_ID]
        return httpx.Response(
            200,
            json={
                "access_token": make_jwt(account_id="account-123", email="person@example.com"),
                "refresh_token": "new-refresh",
                "expires_in": 1800,
            },
        )

    refreshed = refresh_credential(
        make_client(handler),
        credential,
        now_ms=lambda: 1_700_000_000_000,
        request_timeout=2,
    )

    assert refreshed.access_token == make_jwt(account_id="account-123", email="person@example.com")
    assert refreshed.refresh_token == "new-refresh"
    assert refreshed.expires_at == 1_700_001_800_000
    assert refreshed.account_id == "account-123"
    assert refreshed.email == "person@example.com"


def test_refresh_credential_preserves_refresh_token_and_updates_valid_metadata() -> None:
    credential = Credential(
        provider="openai-codex",
        access_token="old-access",
        refresh_token="old-refresh",
        expires_at=1_700_000_000_000,
        account_id="old-account",
        email="old@example.com",
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "access_token": make_jwt(account_id="new-account", email="new@example.com"),
                "expires_in": 1800,
            },
        )

    refreshed = refresh_credential(
        make_client(handler),
        credential,
        now_ms=lambda: 1_700_000_000_000,
        request_timeout=2,
    )

    assert refreshed.refresh_token == "old-refresh"
    assert refreshed.account_id == "new-account"
    assert refreshed.email == "new@example.com"


def test_refresh_credential_ignores_malformed_metadata() -> None:
    credential = Credential(
        provider="openai-codex",
        access_token="old-access",
        refresh_token="old-refresh",
        expires_at=1_700_000_000_000,
        account_id="old-account",
        email="old@example.com",
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "access_token": make_jwt(),
                "expires_in": 1800,
            },
        )

    refreshed = refresh_credential(
        make_client(handler),
        credential,
        now_ms=lambda: 1_700_000_000_000,
        request_timeout=2,
    )

    assert refreshed.account_id == "old-account"
    assert refreshed.email == "old@example.com"


def test_login_with_device_code_uses_jwt_exp_when_expires_in_absent() -> None:
    exp_seconds = 1_700_001_800
    expected_expires_at = exp_seconds * 1000

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/deviceauth/usercode"):
            return httpx.Response(
                200, json={"device_auth_id": "device-123", "user_code": "ABCD-EFGH", "interval": 5}
            )
        if request.url.path.endswith("/deviceauth/token"):
            return httpx.Response(
                200, json={"authorization_code": "auth-123", "code_verifier": "verifier-abc"}
            )
        return httpx.Response(
            200,
            json={
                "access_token": make_jwt(exp=exp_seconds),
                "refresh_token": "refresh-123",
            },
        )

    credential = login_with_device_code(
        make_client(handler),
        output=lambda _: None,
        now_ms=lambda: 1_700_000_000_000,
        sleep=lambda _: None,
        max_poll_seconds=30,
        request_timeout=2,
    )

    assert credential.expires_at == expected_expires_at


def test_refresh_credential_failure_is_sanitized() -> None:
    credential = Credential(
        provider="openai-codex",
        access_token="old-access",
        refresh_token="refresh-secret",
        expires_at=1_700_000_000_000,
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid refresh-secret"})

    with pytest.raises(RefreshTokenError) as exc_info:
        refresh_credential(
            make_client(handler),
            credential,
            now_ms=lambda: 1_700_000_000_000,
            request_timeout=2,
        )

    message = str(exc_info.value)
    assert "refresh failed" in message
    assert "refresh-secret" not in message
