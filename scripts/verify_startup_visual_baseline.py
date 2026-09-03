from __future__ import annotations

import hashlib
from pathlib import Path


# Single authoritative baseline for the current released startup visuals.
# The companion regression test imports the same digest contract so the
# verifier and pytest cannot silently drift apart again.
BASELINE = {
    "src/arenyxa/presentation/startup_splash.py": "46141636071f7adedabbb8ddacc7faaa9381bfdbc059712a72a85ab6ebea0b33",
    "src/arenyxa/presentation/startup_motion_math.py": "b351ae8df000056b6e0bc27f435136a8f9e2743eb2138171c719e4fa7230072f",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    failed = False
    for relative, expected in BASELINE.items():
        path = root / relative
        actual = sha256(path) if path.is_file() else "<missing>"
        state = "PASS" if actual == expected else "FAIL"
        print(f"{state} {relative} {actual}")
        failed = failed or actual != expected
    if failed:
        print("Startup visual baseline changed. Reopen this scope explicitly before accepting the change.")
        return 1
    print("Startup visual baseline matches the current approved smooth-motion baseline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
