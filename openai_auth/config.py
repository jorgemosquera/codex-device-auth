import os
from pathlib import Path

CREDENTIAL_PATH_ENV = "OPENAI_AUTH_CREDENTIAL_PATH"
DEFAULT_CREDENTIAL_DIR = ".openai_auth"
DEFAULT_CREDENTIAL_FILE = "credentials.json"
PROJECT_ROOT = Path(__file__).resolve().parents[1]

CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
PROVIDER_ORIGINATOR = "openclaw"
PROVIDER_USER_AGENT = "openclaw"
DEVICE_CALLBACK_URL = "https://auth.openai.com/deviceauth/callback"


def credential_path() -> Path:
    configured_path = os.environ.get(CREDENTIAL_PATH_ENV)
    if configured_path:
        return Path(configured_path).expanduser()

    return PROJECT_ROOT / DEFAULT_CREDENTIAL_DIR / DEFAULT_CREDENTIAL_FILE
