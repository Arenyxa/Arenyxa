"""Historical compatibility entry point.

The v6/v7/v8 labels are internal engineering milestones. The current public
GitHub release identity is v0.1 and is validated by verify_release_identity.py.
"""

from verify_release_identity import main


if __name__ == "__main__":
    raise SystemExit(main())
