from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from arenyxa.application.developer_identity import write_developer_identity              
from arenyxa.domain.errors import ArenyxaError              


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a Developer Personal key locally; only the public request is shared.")
    parser.add_argument("--developer-id", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    first = getpass.getpass("Developer Personal key passphrase (min 16 chars): ")
    second = getpass.getpass("Confirm passphrase: ")
    if first != second:
        print("Passphrase confirmation does not match.", file=sys.stderr)
        return 2
    try:
        vault, request = write_developer_identity(args.vault, args.request, args.developer_id, args.email, first)
    except ArenyxaError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({
        "created": True,
        "developer_id": request["developer_id"],
        "fingerprint": request["fingerprint"],
        "vault": str(args.vault),
        "public_request": str(args.request),
        "private_key_exported": False,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
