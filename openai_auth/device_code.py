from collections.abc import Callable
from dataclasses import dataclass
import math
import time
from typing import Any

import httpx

from openai_auth.config import (
    CODEX_CLIENT_ID,
    DEVICE_CALLBACK_URL,
    PROVIDER_ORIGINATOR,
    PROVIDER_USER_AGENT,
)
from openai_auth.credentials import (
    SUPPORTED_PROVIDER,
    Credential,
    decode_jwt_expiry,
    decode_jwt_identity,
)
from openai_auth.errors import (
    DeviceCodeNetworkError,
    DeviceCodeResponseError,
    DeviceCodeTimeoutError,
    RefreshTokenError,
)

AUTH_BASE_URL = "https://auth.openai.com"
DEVICE_USERCODE_URL = f"{AUTH_BASE_URL}/api/accounts/deviceauth/usercode"
DEVICE_POLL_URL = f"{AUTH_BASE_URL}/api/accounts/deviceauth/token"
TOKEN_URL = f"{AUTH_BASE_URL}/oauth/token"
VERIFICATION_URI = f"{AUTH_BASE_URL}/codex/device"

DEFAULT_MAX_POLL_SECONDS = 600
DEFAULT_POLL_INTERVAL_SECONDS = 5
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10

_PROVIDER_HEADERS = {
    "originator": PROVIDER_ORIGINATOR,
    "User-Agent": PROVIDER_USER_AGENT,
}


@dataclass(frozen=True)
class DeviceCodeChallenge:
    device_auth_id: str
    user_code: str
    verification_uri: str
    interval_seconds: int


def login_with_device_code(
    client: httpx.Client,
    *,
    output: Callable[[str], None] = print,
    now_ms: Callable[[], int] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    max_poll_seconds: int = DEFAULT_MAX_POLL_SECONDS,
    poll_interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS,
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> Credential:
    current_time_ms = now_ms or _system_now_ms
    challenge = _request_device_code(client, request_timeout)
    output(f"Visit {challenge.verification_uri} and enter code {challenge.user_code}")

    interval_seconds = _poll_interval(challenge.interval_seconds, poll_interval_seconds)
    deadline_ms = current_time_ms() + max_poll_seconds * 1000
    authorization_code, code_verifier = _poll_for_authorization(
        client,
        challenge,
        deadline_ms,
        interval_seconds,
        request_timeout,
        current_time_ms,
        sleep,
    )
    token_data = _exchange_authorization_code(
        client, authorization_code, code_verifier, request_timeout
    )
    return _credential_from_token_response(token_data, current_time_ms())


def _request_device_code(client: httpx.Client, request_timeout: float) -> DeviceCodeChallenge:
    data = _post_json(client, DEVICE_USERCODE_URL, {"client_id": CODEX_CLIENT_ID}, request_timeout)
    return _device_code_challenge_from_response(data)


def _poll_for_authorization(
    client: httpx.Client,
    challenge: DeviceCodeChallenge,
    deadline_ms: int,
    interval_seconds: int,
    request_timeout: float,
    now_ms: Callable[[], int],
    sleep: Callable[[float], None],
) -> tuple[str, str]:
    max_attempts = _max_poll_attempts(deadline_ms, now_ms(), interval_seconds)

    for attempt in range(max_attempts):
        remaining_seconds = _remaining_seconds(deadline_ms, now_ms())
        if remaining_seconds <= 0:
            break

        response = _post_json_raw(
            client,
            DEVICE_POLL_URL,
            {"device_auth_id": challenge.device_auth_id, "user_code": challenge.user_code},
            min(request_timeout, remaining_seconds),
        )
        result = _authorization_from_poll_response(response)
        if result is not None:
            return result

        sleep_seconds = _sleep_seconds_before_next_poll(
            attempt,
            max_attempts,
            interval_seconds,
            deadline_ms,
            now_ms(),
        )
        if sleep_seconds is not None:
            sleep(sleep_seconds)

    raise DeviceCodeTimeoutError("device code login timed out")


def _exchange_authorization_code(
    client: httpx.Client,
    authorization_code: str,
    code_verifier: str,
    request_timeout: float,
) -> dict[str, Any]:
    return _post_form(
        client,
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": DEVICE_CALLBACK_URL,
            "client_id": CODEX_CLIENT_ID,
            "code_verifier": code_verifier,
        },
        request_timeout,
    )


def refresh_credential(
    client: httpx.Client,
    credential: Credential,
    *,
    now_ms: Callable[[], int] | None = None,
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> Credential:
    current_time_ms = now_ms or _system_now_ms
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": credential.refresh_token,
        "client_id": CODEX_CLIENT_ID,
    }
    try:
        token_data = _post_form(client, TOKEN_URL, payload, request_timeout)
        refreshed = _credential_from_refresh_response(token_data, credential, current_time_ms())
    except (DeviceCodeNetworkError, DeviceCodeResponseError) as exc:
        raise RefreshTokenError("refresh failed") from exc

    return refreshed


def _post_json(
    client: httpx.Client, url: str, payload: dict[str, str], request_timeout: float
) -> dict[str, Any]:
    response = _post_json_raw(client, url, payload, request_timeout)
    return _parse_response_json(response)


def _post_json_raw(
    client: httpx.Client, url: str, payload: dict[str, str], request_timeout: float
) -> httpx.Response:
    try:
        return client.post(url, json=payload, headers=_PROVIDER_HEADERS, timeout=request_timeout)
    except httpx.HTTPError as exc:
        raise DeviceCodeNetworkError("device code provider request failed") from exc


def _post_form(
    client: httpx.Client, url: str, payload: dict[str, str], request_timeout: float
) -> dict[str, Any]:
    try:
        response = client.post(
            url, data=payload, headers=_PROVIDER_HEADERS, timeout=request_timeout
        )
    except httpx.HTTPError as exc:
        raise DeviceCodeNetworkError("device code provider request failed") from exc

    if response.status_code < 200 or response.status_code >= 300:
        raise DeviceCodeNetworkError(f"device code provider returned HTTP {response.status_code}")

    return _parse_json_body(response)


def _parse_response_json(response: httpx.Response) -> dict[str, Any]:
    if response.status_code < 200 or response.status_code >= 300:
        raise DeviceCodeNetworkError(f"device code provider returned HTTP {response.status_code}")
    return _parse_json_body(response)


def _parse_json_body(response: httpx.Response) -> dict[str, Any]:
    try:
        data = response.json()
    except ValueError as exc:
        raise DeviceCodeResponseError("device code response is invalid") from exc

    if not isinstance(data, dict):
        raise DeviceCodeResponseError("device code response is invalid")

    return data


def _device_code_challenge_from_response(data: dict[str, Any]) -> DeviceCodeChallenge:
    device_auth_id = data.get("device_auth_id")
    user_code = data.get("user_code") or data.get("usercode")
    raw_interval = data.get("interval", DEFAULT_POLL_INTERVAL_SECONDS)

    if not isinstance(device_auth_id, str) or not device_auth_id:
        raise DeviceCodeResponseError("device code response is invalid")
    if not isinstance(user_code, str) or not user_code:
        raise DeviceCodeResponseError("device code response is invalid")

    interval = _parse_interval(raw_interval)
    if interval is None:
        raise DeviceCodeResponseError("device code response is invalid")

    return DeviceCodeChallenge(
        device_auth_id=device_auth_id,
        user_code=user_code,
        verification_uri=VERIFICATION_URI,
        interval_seconds=interval,
    )


def _parse_interval(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str):
        try:
            parsed = int(value)
            return parsed if parsed > 0 else None
        except ValueError:
            return None
    return None


def _authorization_from_poll_response(response: httpx.Response) -> tuple[str, str] | None:
    if response.status_code in (403, 404):
        return None

    if response.status_code != 200:
        raise DeviceCodeNetworkError(f"device code poll returned HTTP {response.status_code}")

    data = _parse_json_body(response)
    authorization_code = data.get("authorization_code")
    code_verifier = data.get("code_verifier")

    if not isinstance(authorization_code, str) or not authorization_code:
        raise DeviceCodeResponseError("device code poll response is invalid")
    if not isinstance(code_verifier, str) or not code_verifier:
        raise DeviceCodeResponseError("device code poll response is invalid")

    return authorization_code, code_verifier


def _credential_from_token_response(data: dict[str, Any], now_ms: int) -> Credential:
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    expires_in = data.get("expires_in")

    if not isinstance(access_token, str) or not access_token:
        raise DeviceCodeResponseError("token response is invalid")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise DeviceCodeResponseError("token response is invalid")

    expires_at = _resolve_expires_at(expires_in, access_token, now_ms)

    account_id, email = decode_jwt_identity(access_token)

    return Credential(
        provider=SUPPORTED_PROVIDER,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        account_id=account_id,
        email=email,
    )


def _credential_from_refresh_response(
    data: dict[str, Any], current: Credential, now_ms: int
) -> Credential:
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token", current.refresh_token)
    expires_in = data.get("expires_in")

    if not isinstance(access_token, str) or not access_token:
        raise DeviceCodeResponseError("token response is invalid")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise DeviceCodeResponseError("token response is invalid")

    expires_at = _resolve_expires_at(expires_in, access_token, now_ms)

    new_account_id, new_email = decode_jwt_identity(access_token)
    account_id = _metadata_value(new_account_id, current.account_id)
    email = _metadata_value(new_email, current.email)

    return Credential(
        provider=current.provider,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        account_id=account_id,
        email=email,
    )


def _resolve_expires_at(expires_in: Any, access_token: str, now_ms: int) -> int:
    if not isinstance(expires_in, bool) and isinstance(expires_in, int) and expires_in > 0:
        return now_ms + expires_in * 1000

    jwt_expiry = decode_jwt_expiry(access_token)
    if jwt_expiry is not None:
        return jwt_expiry

    raise DeviceCodeResponseError("token response is invalid")


def _metadata_value(value: str | None, fallback: str | None) -> str | None:
    return value if value is not None else fallback


def _max_poll_attempts(deadline_ms: int, start_ms: int, interval_seconds: int) -> int:
    duration_ms = deadline_ms - start_ms
    if duration_ms <= 0:
        raise ValueError("max_poll_seconds must be positive")
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")

    return max(1, math.ceil(duration_ms / (interval_seconds * 1000)))


def _sleep_seconds_before_next_poll(
    attempt: int,
    max_attempts: int,
    interval_seconds: int,
    deadline_ms: int,
    now_ms: int,
) -> float | None:
    if attempt >= max_attempts - 1:
        return None

    remaining_ms = deadline_ms - now_ms
    if remaining_ms <= 0:
        return None

    return min(interval_seconds, remaining_ms / 1000)


def _remaining_seconds(deadline_ms: int, now_ms: int) -> float:
    return (deadline_ms - now_ms) / 1000


def _poll_interval(provider_interval_seconds: int, configured_interval_seconds: int) -> int:
    if configured_interval_seconds <= 0:
        raise ValueError("poll_interval_seconds must be positive")

    return max(provider_interval_seconds, configured_interval_seconds)


def _system_now_ms() -> int:
    return int(time.time() * 1000)
