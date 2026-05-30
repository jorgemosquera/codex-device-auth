# codex-device-auth

OpenAI Codex device-code authentication for Python. Authenticate with your ChatGPT account and use the resulting token to drive real LLM inference — no paid API key required.

This is not an official OpenAI library, not a production login system, and not intended for shared-user deployments. It is a learning project for studying the auth lifecycle end to end.

## What this project demonstrates

OpenAI's device-code flow issues a standard JWT access token. That token can drive real LLM inference against the Codex Responses API — no paid API key required. The auth mechanism differs at login time, but once you hold a token the call surface is identical.

This project validates the full lifecycle:

1. **Device-code auth** — requests a user code from `auth.openai.com`, polls until the user authorizes in a browser, then exchanges the server-returned authorization code and `code_verifier` for a JWT access token.
2. **Token lifecycle** — JWT-based expiry detection, automatic refresh before requests, atomic credential file writes with `0600` permissions.
3. **Real inference** — the `test` command proves the stored token drives live GPT-5.5 completions via the Codex Responses API (SSE streaming).
4. **LangChain integration** — `CodexChatModel` makes the token-based auth transparent. Standard LangChain patterns (`invoke`, `stream`, LangGraph `StateGraph`) work without modification.

## Installation

```bash
uv add git+https://github.com/jamosquera/codex-device-auth
# or
pip install git+https://github.com/jamosquera/codex-device-auth
```

## Setup (this repo)

```bash
uv sync --dev
```

## Commands

```bash
codex-device-auth login
codex-device-auth status
codex-device-auth refresh
codex-device-auth test
codex-device-auth logout
```

Or via the module:

```bash
uv run python -m codex_device_auth login
```

Credentials default to `~/.codex_device_auth/default/credentials.json`. Set
`CODEX_DEVICE_AUTH_PROJECT` to isolate credentials per project:

```bash
export CODEX_DEVICE_AUTH_PROJECT=my-project
# credentials will be stored at ~/.codex_device_auth/my-project/credentials.json
```

Set `CODEX_DEVICE_AUTH_CREDENTIAL_PATH` to an explicit path to override both:

```bash
export CODEX_DEVICE_AUTH_CREDENTIAL_PATH=/path/to/credentials.json
```

Pass `--credential-path` to any command for a one-off override.

The CLI keeps output concise and must not print access or refresh token values.

## Using with LangChain

```bash
uv add langchain-core langgraph
```

```python
import httpx
from langchain_core.messages import HumanMessage, SystemMessage
from codex_device_auth import CodexChatModel, load_credentials, credential_path

credential = load_credentials(credential_path())

with httpx.Client() as client:
    model = CodexChatModel(credential=credential, client=client)

    # invoke
    response = model.invoke([HumanMessage(content="What is 2 + 2?")])
    print(response.content)

    # system prompt
    response = model.invoke([
        SystemMessage(content="You are a pirate. Always respond in pirate speak."),
        HumanMessage(content="What is the capital of France?"),
    ])
    print(response.content)

    # streaming
    for chunk in model.stream([HumanMessage(content="Count from 1 to 5.")]):
        print(chunk.content, end="", flush=True)
```

See [`tests/live/codex_langgraph_demo.py`](tests/live/codex_langgraph_demo.py) for a complete
example including a LangGraph `StateGraph` workflow.

## Development

```bash
uv run python -B -m pytest
uv run ruff check .
```

### Live Protocol Validation

Before writing or updating unit tests for any auth protocol step, validate
the real server response using the observation scripts in `tests/live/`:

```bash
uv run python tests/live/validate_usercode.py
uv run python tests/live/validate_poll.py     # requires DEVICE_AUTH_ID and USER_CODE env vars
uv run python tests/live/validate_exchange.py # requires AUTHORIZATION_CODE and CODE_VERIFIER env vars
uv run python tests/live/validate_runtime.py  # requires saved credentials (run login first)
```

These scripts call the real `auth.openai.com` endpoints and print labeled
request/response details. No assertions — use them to confirm field names and
response shapes before writing mocks. Re-run if live login starts failing or
the upstream auth protocol changes.

### LangChain / LangGraph Demo

`CodexChatModel` in [`codex_device_auth/codex_chat_model.py`](codex_device_auth/codex_chat_model.py)
is a LangChain `BaseChatModel` subclass that routes calls through the Codex Responses endpoint
using your stored credentials. It supports `invoke()` and `stream()`.

```bash
uv run python tests/live/codex_langgraph_demo.py
```

The demo exercises four scenarios:

1. Basic `model.invoke([HumanMessage(...)])`
2. System prompt via `SystemMessage` (maps to the Codex `instructions` field)
3. Token-by-token streaming with `model.stream()`
4. A `StateGraph` workflow using the model as a node

Requires saved credentials — run `codex-device-auth login` first.
