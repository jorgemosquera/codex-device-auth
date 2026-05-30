# openai-auth

Local learning project for experimenting with an OpenAI-style device-code auth flow in Python.

This is not an official OpenAI API authentication replacement, not a production login system, and not intended for shared-user deployments. It stores local credentials so you can study the auth lifecycle end to end.

## What this project demonstrates

OpenAI's device-code flow issues a standard JWT access token. That token can drive real LLM inference against the Codex Responses API — no paid API key required. The auth mechanism differs at login time, but once you hold a token the call surface is identical.

This project validates the full lifecycle:

1. **Device-code auth** — requests a user code from `auth.openai.com`, polls until the user authorizes in a browser, then exchanges the server-returned authorization code and `code_verifier` for a JWT access token.
2. **Token lifecycle** — JWT-based expiry detection, automatic refresh before requests, atomic credential file writes with `0600` permissions.
3. **Real inference** — the `test` command proves the stored token drives live GPT-5.5 completions via the Codex Responses API (SSE streaming).
4. **LangChain integration** — `CodexChatModel` makes the token-based auth transparent. Standard LangChain patterns (`invoke`, `stream`, LangGraph `StateGraph`) work without modification.

## Setup

```bash
uv sync --dev
```

## Commands

```bash
uv run python -m openai_auth login
uv run python -m openai_auth status
uv run python -m openai_auth refresh
uv run python -m openai_auth test
uv run python -m openai_auth logout
```

Credentials default to `.openai_auth/credentials.json` under the project root. Set `OPENAI_AUTH_CREDENTIAL_PATH` or pass `--credential-path` in tests and experiments to use another file.

The CLI keeps output concise and must not print access or refresh token values.

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

`CodexChatModel` in `openai_auth/codex_chat_model.py` is a LangChain
`BaseChatModel` subclass that routes calls through the Codex Responses
endpoint using your stored credentials. It supports `invoke()` and `stream()`.

```bash
uv run python tests/live/codex_langgraph_demo.py
```

The demo exercises four scenarios:

1. Basic `model.invoke([HumanMessage(...)])`
2. System prompt via `SystemMessage` (maps to the Codex `instructions` field)
3. Token-by-token streaming with `model.stream()`
4. A `StateGraph` workflow using the model as a node

Requires saved credentials — run `login` first.
