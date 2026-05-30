# openai-auth

Local learning project for experimenting with an OpenAI-style device-code auth flow in Python.

This is not an official OpenAI API authentication replacement, not a production login system, and not intended for shared-user deployments. It stores local credentials so you can study the auth lifecycle end to end.

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
