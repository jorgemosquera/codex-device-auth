"""OpenAI Codex device-code authentication library."""

from codex_device_auth.codex_chat_model import CodexChatModel
from codex_device_auth.config import credential_path
from codex_device_auth.credentials import Credential, load_credentials, save_credentials
from codex_device_auth.device_code import login_with_device_code

__all__ = [
    "__version__",
    "CodexChatModel",
    "Credential",
    "credential_path",
    "load_credentials",
    "login_with_device_code",
    "save_credentials",
]

__version__ = "0.1.0"
