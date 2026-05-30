from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx

from openai_auth.credentials import (
    Credential,
    is_expired,
    is_near_expiry,
    load_credentials,
    redact_secrets,
    save_credentials,
)
from openai_auth.config import PROVIDER_ORIGINATOR, PROVIDER_USER_AGENT
from openai_auth.device_code import DEFAULT_REQUEST_TIMEOUT_SECONDS, refresh_credential
from openai_auth.errors import CredentialError, RefreshTokenError, RuntimeRequestError

RUNTIME_TEST_URL = "https://chatgpt.com/backend-api/accounts/check"
MAX_RESPONSE_DETAIL_LENGTH = 200


@dataclass(frozen=True)
class AuthStatus:
    state: str
    account_id: str | None = None
    email: str | None = None


@dataclass(frozen=True)
class RuntimeTestResult:
    ok: bool
    status_code: int


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


def build_auth_headers(credential: Credential) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {credential.access_token}",
        "originator": PROVIDER_ORIGINATOR,
        "User-Agent": PROVIDER_USER_AGENT,
    }
    if credential.account_id is not None:
        headers["chatgpt-account-id"] = credential.account_id

    return headers


def run_test_request(
    client: httpx.Client,
    *,
    path: Path | None = None,
    now_ms: Callable[[], int],
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> RuntimeTestResult:
    credential = load_credentials(path)
    if credential is None:
        raise CredentialError("not logged in")

    usable_credential = _ensure_fresh_credential(client, credential, path, now_ms, request_timeout)
    response = _send_runtime_test_request(client, usable_credential, request_timeout)
    if response.status_code < 200 or response.status_code >= 300:
        message = _runtime_rejection_message(response, usable_credential)
        raise RuntimeRequestError(message)

    return RuntimeTestResult(ok=True, status_code=response.status_code)


def _ensure_fresh_credential(
    client: httpx.Client,
    credential: Credential,
    path: Path | None,
    now_ms: Callable[[], int],
    request_timeout: float,
) -> Credential:
    now = now_ms()
    if not is_near_expiry(credential, now_ms=now):
        return credential

    try:
        refreshed = refresh_credential(
            client,
            credential,
            now_ms=now_ms,
            request_timeout=request_timeout,
        )
    except RefreshTokenError:
        raise RuntimeRequestError("refresh failed before runtime request") from None

    try:
        save_credentials(refreshed, path)
    except CredentialError:
        raise RuntimeRequestError("credential file could not be saved") from None

    return refreshed


def _send_runtime_test_request(
    client: httpx.Client, credential: Credential, request_timeout: float
) -> httpx.Response:
    headers = build_auth_headers(credential)
    try:
        return client.get(RUNTIME_TEST_URL, headers=headers, timeout=request_timeout)
    except httpx.HTTPError:
        message = redact_secrets("runtime request failed", credential)
        raise RuntimeRequestError(message) from None


def _runtime_rejection_message(response: httpx.Response, credential: Credential) -> str:
    detail = _response_detail(response)
    message = f"runtime request rejected with HTTP {response.status_code}: {detail}"
    return redact_secrets(message, credential)


def _response_detail(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return "request rejected"

    if isinstance(data, dict):
        detail = _safe_error_detail(data)
        if detail is not None:
            return detail

    return "request rejected"


def _safe_error_detail(data: dict[object, object]) -> str | None:
    error = data.get("error")
    if isinstance(error, str) and error:
        return _truncate(error)
    if not isinstance(error, dict):
        return None

    message = error.get("message")
    if isinstance(message, str) and message:
        return _truncate(message)

    return None


def _truncate(value: str) -> str:
    if len(value) <= MAX_RESPONSE_DETAIL_LENGTH:
        return value

    return f"{value[:MAX_RESPONSE_DETAIL_LENGTH]}..."
