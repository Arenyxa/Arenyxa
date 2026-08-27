from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arenyxa.application.adaptive_selector_benchmark import AdaptiveSelectorBenchmark


def main() -> int:
    result = AdaptiveSelectorBenchmark().run()
    print(json.dumps(result.snapshot(), ensure_ascii=False, indent=2, default=str))
    return 0 if result.passed_default_gate else 1


if __name__ == "__main__":
    raise SystemExit(main())
