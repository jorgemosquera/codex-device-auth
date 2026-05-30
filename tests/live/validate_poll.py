import os
import re
import sys

import httpx

from openai_auth.config import PROVIDER_ORIGINATOR, PROVIDER_USER_AGENT

POLL_URL = "https://auth.openai.com/api/accounts/deviceauth/token"


def _redact(text: str) -> str:
    return re.sub(r"\b(?:access|refresh)-[A-Za-z0-9._-]+\b", "[REDACTED]", text)


def main() -> int:
    device_auth_id = os.environ.get("DEVICE_AUTH_ID")
    user_code = os.environ.get("USER_CODE")

    if not device_auth_id or not user_code:
        print(
            "Usage: DEVICE_AUTH_ID=<id> USER_CODE=<code> uv run python tests/live/validate_poll.py",
            file=sys.stderr,
        )
        print(
            "Run validate_usercode.py first to obtain DEVICE_AUTH_ID and USER_CODE.",
            file=sys.stderr,
        )
        return 1

    payload = {"device_auth_id": device_auth_id, "user_code": user_code}
    headers = {"originator": PROVIDER_ORIGINATOR, "User-Agent": PROVIDER_USER_AGENT}

    print("=== REQUEST ===")
    print(f"URL: {POLL_URL}")
    print(f"Headers: {headers}")
    print(f"Body: {payload}")

    try:
        with httpx.Client() as client:
            response = client.post(POLL_URL, json=payload, headers=headers, timeout=10)
    except httpx.HTTPError as exc:
        print(f"\nNetwork error: {exc}", file=sys.stderr)
        return 1

    print("\n=== RESPONSE ===")
    print(f"Status: {response.status_code}")
    print(f"Body: {_redact(response.text)}")

    print("\n=== FIELD CHECK ===")
    print(f"  Status code while pending (expect 403 or 404): {response.status_code}")
    if response.status_code == 200:
        try:
            data = response.json()
            print(f"  authorization_code present: {'authorization_code' in data}")
            print(f"  code_verifier present:      {'code_verifier' in data}")
        except ValueError:
            print("  (response is not valid JSON)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
