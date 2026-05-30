import re
import sys

import httpx

CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
USERCODE_URL = "https://auth.openai.com/api/accounts/deviceauth/usercode"
ORIGINATOR = "openclaw"
USER_AGENT = "openclaw"


def _redact(text: str) -> str:
    return re.sub(r"\b(?:access|refresh)-[A-Za-z0-9._-]+\b", "[REDACTED]", text)


def main() -> int:
    payload = {"client_id": CODEX_CLIENT_ID}
    headers = {"originator": ORIGINATOR, "User-Agent": USER_AGENT}

    print("=== REQUEST ===")
    print(f"URL: {USERCODE_URL}")
    print(f"Headers: {headers}")
    print(f"Body: {payload}")

    try:
        with httpx.Client() as client:
            response = client.post(USERCODE_URL, json=payload, headers=headers, timeout=10)
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
            print(f"  device_auth_id present: {'device_auth_id' in data}")
            print(f"  user_code present:      {'user_code' in data or 'usercode' in data}")
            print(f"  interval present:       {'interval' in data}")
            print(f"  verification_uri present (should be absent): {'verification_uri' in data}")
        except ValueError:
            print("  (response is not valid JSON)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
