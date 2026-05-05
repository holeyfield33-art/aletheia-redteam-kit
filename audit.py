from __future__ import annotations

import sys

from kit import runner


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if "--mode" not in args:
        args = ["--mode", "website", *args]
    if "--target" in args:
        args[args.index("--target")] = "--target-url"
    sys.argv = [sys.argv[0], *args]
    return runner.cli()


if __name__ == "__main__":
    raise SystemExit(main())