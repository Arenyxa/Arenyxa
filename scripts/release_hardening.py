from __future__ import annotations

import argparse
import json
from pathlib import Path

from arenyxa.release_hardening import ReleasePolicy, compatibility_matrix


def main() -> int:
    parser = argparse.ArgumentParser(description="Arenyxa Phase-12 release hardening inspector")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = {"release_policy": ReleasePolicy().to_dict(), "compatibility_matrix": compatibility_matrix()}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print("Arenyxa Phase-12 release policy")
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
