import sys

import httpx

from codex_device_auth.config import credential_path
from codex_device_auth.credentials import load_credentials, redact_secrets
from codex_device_auth.runtime import build_auth_headers

RUNTIME_TEST_URL = "https://chatgpt.com/backend-api/accounts/check"


def main() -> int:
    credential = load_credentials(credential_path())
    if credential is None:
        print("not logged in — run 'uv run openai-auth login' first", file=sys.stderr)
        return 1

    headers = build_auth_headers(credential)
    safe_headers = {k: ("[REDACTED]" if k == "Authorization" else v) for k, v in headers.items()}

    print("=== REQUEST ===")
    print(f"URL: {RUNTIME_TEST_URL}")
    print(f"Headers: {safe_headers}")

    try:
        with httpx.Client() as client:
            response = client.get(RUNTIME_TEST_URL, headers=headers, timeout=10)
    except httpx.HTTPError as exc:
        message = redact_secrets(str(exc), credential)
        print(f"\nNetwork error: {message}", file=sys.stderr)
        return 1

    print("\n=== RESPONSE ===")
    print(f"Status: {response.status_code}")
    safe_body = redact_secrets(response.text, credential)
    print(f"Body: {safe_body}")

    print("\n=== FIELD CHECK ===")
    print(f"  Accepted (expect 200): {response.status_code == 200}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
