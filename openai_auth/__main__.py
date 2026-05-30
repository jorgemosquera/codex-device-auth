from collections.abc import Sequence
import argparse
import sys
import time

import httpx

from openai_auth.errors import AuthError
from openai_auth.runtime import run_test_request


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m openai_auth")
    parser.add_argument("command", choices=["test"])
    args = parser.parse_args(argv)

    if args.command == "test":
        return _run_test_command()

    return 2


def _run_test_command() -> int:
    with httpx.Client() as client:
        try:
            result = run_test_request(client, now_ms=_now_ms)
        except AuthError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    print(f"authenticated request succeeded: HTTP {result.status_code}")
    return 0


def _now_ms() -> int:
    return int(time.time() * 1000)


if __name__ == "__main__":
    raise SystemExit(main())
