from collections.abc import Callable
from dataclasses import dataclass
import math
import time
from typing import Any

import httpx

from openai_auth.credentials import Credential
from openai_auth.errors import (
    DeviceCodeDeniedError,
    DeviceCodeNetworkError,
    DeviceCodeResponseError,
    DeviceCodeTimeoutError,
    RefreshTokenError,
)

PROVIDER = "openai-codex"
AUTH_BASE_URL = "https://auth.openai.com"
DEVICE_CODE_URL = f"{AUTH_BASE_URL}/oauth/device/code"
DEVICE_POLL_URL = f"{AUTH_BASE_URL}/oauth/device/poll"
TOKEN_URL = f"{AUTH_BASE_URL}/oauth/token"
DEFAULT_MAX_POLL_SECONDS = 600
DEFAULT_POLL_INTERVAL_SECONDS = 5
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class DeviceCodeChallenge:
    device_code: str
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
    authorization_code = _poll_for_authorization_code(
        client,
        challenge.device_code,
        deadline_ms,
        interval_seconds,
        request_timeout,
        current_time_ms,
        sleep,
    )
    token_data = _exchange_authorization_code(client, authorization_code, request_timeout)
    return _credential_from_token_response(token_data, current_time_ms())


def _request_device_code(client: httpx.Client, request_timeout: float) -> DeviceCodeChallenge:
    data = _post_json(client, DEVICE_CODE_URL, {"provider": PROVIDER}, request_timeout)
    return _device_code_challenge_from_response(data)


def _poll_for_authorization_code(
    client: httpx.Client,
    device_code: str,
    deadline_ms: int,
    interval_seconds: int,
    request_timeout: float,
    now_ms: Callable[[], int],
    sleep: Callable[[float], None],
) -> str:
    max_attempts = _max_poll_attempts(deadline_ms, now_ms(), interval_seconds)

    for attempt in range(max_attempts):
        remaining_seconds = _remaining_seconds(deadline_ms, now_ms())
        if remaining_seconds <= 0:
            break

        data = _post_json(
            client,
            DEVICE_POLL_URL,
            {"device_code": device_code},
            min(request_timeout, remaining_seconds),
        )
        authorization_code = _authorization_code_from_poll_response(data)
        if authorization_code is not None:
            return authorization_code

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
    client: httpx.Client, authorization_code: str, request_timeout: float
) -> dict[str, Any]:
    return _post_json(
        client,
        TOKEN_URL,
        {"authorization_code": authorization_code, "grant_type": "authorization_code"},
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
    payload = {"refresh_token": credential.refresh_token, "grant_type": "refresh_token"}
    try:
        token_data = _post_json(client, TOKEN_URL, payload, request_timeout)
        refreshed = _credential_from_refresh_response(token_data, credential, current_time_ms())
    except (DeviceCodeNetworkError, DeviceCodeResponseError) as exc:
        raise RefreshTokenError("refresh failed") from exc

    return refreshed


def _post_json(
    client: httpx.Client, url: str, payload: dict[str, str], request_timeout: float
) -> dict[str, Any]:
    try:
        response = client.post(url, json=payload, timeout=request_timeout)
    except httpx.HTTPError as exc:
        raise DeviceCodeNetworkError("device code provider request failed") from exc

    if response.status_code < 200 or response.status_code >= 300:
        raise DeviceCodeNetworkError(f"device code provider returned HTTP {response.status_code}")

    try:
        data = response.json()
    except ValueError as exc:
        raise DeviceCodeResponseError("device code response is invalid") from exc

    if not isinstance(data, dict):
        raise DeviceCodeResponseError("device code response is invalid")

    return data


def _device_code_challenge_from_response(data: dict[str, Any]) -> DeviceCodeChallenge:
    device_code = data.get("device_code")
    user_code = data.get("user_code")
    verification_uri = data.get("verification_uri")
    interval = data.get("interval", DEFAULT_POLL_INTERVAL_SECONDS)

    if not isinstance(device_code, str) or not device_code:
        raise DeviceCodeResponseError("device code response is invalid")
    if not isinstance(user_code, str) or not user_code:
        raise DeviceCodeResponseError("device code response is invalid")
    if not isinstance(verification_uri, str) or not verification_uri:
        raise DeviceCodeResponseError("device code response is invalid")
    if not isinstance(interval, int) or interval <= 0:
        raise DeviceCodeResponseError("device code response is invalid")

    return DeviceCodeChallenge(
        device_code=device_code,
        user_code=user_code,
        verification_uri=verification_uri,
        interval_seconds=interval,
    )


def _authorization_code_from_poll_response(data: dict[str, Any]) -> str | None:
    status = data.get("status")
    if status == "authorization_pending":
        return None
    if status == "denied":
        raise DeviceCodeDeniedError("device code authorization denied")
    if status == "failed":
        raise DeviceCodeDeniedError("device code authorization failed")
    if status != "authorized":
        raise DeviceCodeResponseError("device code poll response is invalid")

    authorization_code = data.get("authorization_code")
    if not isinstance(authorization_code, str) or not authorization_code:
        raise DeviceCodeResponseError("device code poll response is invalid")

    return authorization_code


def _credential_from_token_response(data: dict[str, Any], now_ms: int) -> Credential:
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    expires_in = data.get("expires_in")
    account_id = data.get("account_id")
    email = data.get("email")

    if not isinstance(access_token, str) or not access_token:
        raise DeviceCodeResponseError("token response is invalid")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise DeviceCodeResponseError("token response is invalid")
    if not isinstance(expires_in, int) or expires_in <= 0:
        raise DeviceCodeResponseError("token response is invalid")
    return Credential(
        provider=PROVIDER,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=now_ms + expires_in * 1000,
        account_id=_optional_string(account_id),
        email=_optional_string(email),
    )


def _credential_from_refresh_response(
    data: dict[str, Any], current: Credential, now_ms: int
) -> Credential:
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token", current.refresh_token)
    expires_in = data.get("expires_in")
    account_id = _metadata_value(data.get("account_id"), current.account_id)
    email = _metadata_value(data.get("email"), current.email)

    if not isinstance(access_token, str) or not access_token:
        raise DeviceCodeResponseError("token response is invalid")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise DeviceCodeResponseError("token response is invalid")
    if not isinstance(expires_in, int) or expires_in <= 0:
        raise DeviceCodeResponseError("token response is invalid")

    return Credential(
        provider=current.provider,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=now_ms + expires_in * 1000,
        account_id=account_id,
        email=email,
    )


def _metadata_value(value: Any, fallback: str | None) -> str | None:
    extracted = _optional_string(value)
    if extracted is None:
        return fallback

    return extracted


def _optional_string(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value

    return None


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
