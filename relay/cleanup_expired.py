#!/usr/bin/env python3
"""Delete expired relay-owned receipt files for the systemd timer."""

try:
    from .app import config_from_environment, cleanup_expired
except ImportError:  # pragma: no cover - direct script execution
    from app import config_from_environment, cleanup_expired


def main() -> int:
    config = config_from_environment()
    print("removed %d expired relay file(s)" % cleanup_expired(config), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
