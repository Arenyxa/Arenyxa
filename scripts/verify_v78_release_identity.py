"""Compatibility entry point retained for automation that still calls the v7.8 gate name."""

from verify_v80_release_identity import main


if __name__ == "__main__":
    raise SystemExit(main())
