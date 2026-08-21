from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from keeper.pass_b.pilot import run_darksage_pilot


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the isolated Keeper Completion Pass B pilot."
    )
    parser.add_argument("--data-directory", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    options = parser.parse_args()
    result = run_darksage_pilot(
        options.data_directory, options.evidence
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("result") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
