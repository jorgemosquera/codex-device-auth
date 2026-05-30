import os
from pathlib import Path

CREDENTIAL_PATH_ENV = "CODEX_DEVICE_AUTH_CREDENTIAL_PATH"
DEFAULT_CREDENTIAL_DIR = ".codex_device_auth"
DEFAULT_CREDENTIAL_FILE = "credentials.json"
PROJECT_ROOT = Path(__file__).resolve().parents[1]

CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
PROVIDER_ORIGINATOR = "openclaw"
PROVIDER_USER_AGENT = "openclaw"
DEVICE_CALLBACK_URL = "https://auth.openai.com/deviceauth/callback"

CODEX_RESPONSES_URL = "https://chatgpt.com/backend-api/codex/responses"
CODEX_MODEL = "gpt-5.5"
CODEX_TEST_PROMPT = "respond with a single word: ok"


def credential_path() -> Path:
    configured_path = os.environ.get(CREDENTIAL_PATH_ENV)
    if configured_path:
        return Path(configured_path).expanduser()

    return PROJECT_ROOT / DEFAULT_CREDENTIAL_DIR / DEFAULT_CREDENTIAL_FILE
