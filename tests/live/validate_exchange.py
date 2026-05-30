import os
import re
import sys

import httpx

from codex_device_auth.config import (
    CODEX_CLIENT_ID,
    DEVICE_CALLBACK_URL,
    PROVIDER_ORIGINATOR,
    PROVIDER_USER_AGENT,
)
from codex_device_auth.credentials import decode_jwt_payload

TOKEN_URL = "https://auth.openai.com/oauth/token"


def _redact(text: str) -> str:
    return re.sub(r"\b(?:access|refresh)-[A-Za-z0-9._-]+\b", "[REDACTED]", text)


def main() -> int:
    authorization_code = os.environ.get("AUTHORIZATION_CODE")
    code_verifier = os.environ.get("CODE_VERIFIER")

    if not authorization_code or not code_verifier:
        print(
            "Usage: AUTHORIZATION_CODE=<code> CODE_VERIFIER=<verifier> "
            "uv run python tests/live/validate_exchange.py",
            file=sys.stderr,
        )
        print(
            "Run validate_poll.py until it returns HTTP 200 to obtain these values.",
            file=sys.stderr,
        )
        return 1

    payload = {
        "grant_type": "authorization_code",
        "code": authorization_code,
        "redirect_uri": DEVICE_CALLBACK_URL,
        "client_id": CODEX_CLIENT_ID,
        "code_verifier": code_verifier,
    }
    headers = {"originator": PROVIDER_ORIGINATOR, "User-Agent": PROVIDER_USER_AGENT}

    print("=== REQUEST ===")
    print(f"URL: {TOKEN_URL}")
    print(f"Headers: {headers}")
    print(f"Body (form): {payload}")

    try:
        with httpx.Client() as client:
            response = client.post(TOKEN_URL, data=payload, headers=headers, timeout=10)
    except httpx.HTTPError as exc:
        print(f"\nNetwork error: {exc}", file=sys.stderr)
        return 1

    print("\n=== RESPONSE ===")
    print(f"Status: {response.status_code}")
    print(f"Body: {_redact(response.text)}")

    if response.status_code == 200:
        try:
            data = response.json()
            print("\n=== FIELD CHECK ===")
            print(f"  access_token present:  {'access_token' in data}")
            print(f"  refresh_token present: {'refresh_token' in data}")
            print(f"  expires_in present:    {'expires_in' in data}")
            print(f"  account_id in JSON (should be absent): {'account_id' in data}")
            print(f"  email in JSON (should be absent):      {'email' in data}")

            access_token = data.get("access_token", "")
            if access_token:
                claims = decode_jwt_payload(access_token)
                print("\n=== JWT CLAIMS (middle segment) ===")
                if claims:
                    auth_claims = claims.get("https://api.openai.com/auth", {})
                    profile_claims = claims.get("https://api.openai.com/profile", {})
                    print(f"  https://api.openai.com/auth:    {auth_claims}")
                    print(f"  https://api.openai.com/profile: {profile_claims}")
                    print(f"  exp: {claims.get('exp')}")
                else:
                    print("  (could not decode JWT payload)")
        except ValueError:
            print("  (response is not valid JSON)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
