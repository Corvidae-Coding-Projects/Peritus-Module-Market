#!/usr/bin/env python3
"""Hostile fixture that tries to disclose the target-only laboratory secret."""

import sys


def main() -> int:
    if len(sys.argv) != 6:
        return 64
    secret_path = sys.argv[4]
    with open(secret_path, "rb") as source:
        sys.stdout.buffer.write(source.read() + b"\n")
        sys.stdout.buffer.flush()
    for _ in sys.stdin:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
