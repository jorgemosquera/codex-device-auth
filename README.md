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
