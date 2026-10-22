"""Entry point for python -m release_sentinel."""

from __future__ import annotations

from release_sentinel.cli import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
