import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from curl_cffi import requests as curl_requests

from openai_auth.config import (
    CODEX_MODEL,
    CODEX_RESPONSES_URL,
    CODEX_TEST_PROMPT,
    PROVIDER_ORIGINATOR,
    PROVIDER_USER_AGENT,
)
from openai_auth.credentials import (
    Credential,
    is_expired,
    is_near_expiry,
    load_credentials,
    redact_secrets,
    save_credentials,
)
from openai_auth.device_code import DEFAULT_REQUEST_TIMEOUT_SECONDS, refresh_credential
from openai_auth.errors import CredentialError, RefreshTokenError, RuntimeRequestError


@dataclass(frozen=True)
class AuthStatus:
    state: str
    account_id: str | None = None
    email: str | None = None


@dataclass(frozen=True)
class RuntimeTestResult:
    ok: bool
    status_code: int
    response_text: str = ""


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
    response_text = _send_codex_test_request(usable_credential, request_timeout)
    return RuntimeTestResult(ok=True, status_code=200, response_text=response_text)


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


def _send_codex_test_request(credential: Credential, request_timeout: float) -> str:
    headers = build_auth_headers(credential)
    headers["content-type"] = "application/json"
    headers["OpenAI-Beta"] = "responses=experimental"
    headers["accept"] = "text/event-stream"

    body = {
        "model": CODEX_MODEL,
        "store": False,
        "stream": True,
        "instructions": "You are a helpful assistant.",
        "input": [
            {
                "role": "user",
                "content": [{"type": "input_text", "text": CODEX_TEST_PROMPT}],
            }
        ],
        "text": {"verbosity": "low"},
        "include": ["reasoning.encrypted_content"],
        "tool_choice": "auto",
        "parallel_tool_calls": True,
    }

    try:
        response = curl_requests.post(
            CODEX_RESPONSES_URL,
            headers=headers,
            json=body,
            impersonate="chrome",
            timeout=request_timeout,
            stream=True,
        )
    except Exception as exc:
        message = redact_secrets("codex request failed", credential)
        raise RuntimeRequestError(message) from exc

    if response.status_code < 200 or response.status_code >= 300:
        message = redact_secrets(
            f"codex request rejected with HTTP {response.status_code}", credential
        )
        raise RuntimeRequestError(message)

    return _parse_sse_text(response, credential)


def _parse_sse_text(response: Any, credential: Credential) -> str:
    text_parts: list[str] = []
    for raw_line in response.iter_lines():
        line = raw_line if isinstance(raw_line, bytes) else raw_line.encode()
        if not line.startswith(b"data: "):
            continue
        payload = line[6:]
        if payload == b"[DONE]":
            break
        try:
            event = json.loads(payload)
        except ValueError:
            continue
        if event.get("type") == "response.output_text.delta":
            delta = event.get("delta", "")
            if isinstance(delta, str):
                text_parts.append(delta)

    result = "".join(text_parts)
    if not result:
        raise RuntimeRequestError("codex response contained no text")
    return redact_secrets(result, credential)
