"""`python -m whalescan` shares the console-script entry point."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
