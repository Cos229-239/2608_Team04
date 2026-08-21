from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from keeper.authority_service.client import ProductionAuthorityServiceClient
from keeper.pass_b.application import PassBApplication
from keeper.pass_b.desktop import PassBDesktop


def main() -> int:
    application = PassBApplication(
        authority_client=ProductionAuthorityServiceClient()
    )
    PassBDesktop(application).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
