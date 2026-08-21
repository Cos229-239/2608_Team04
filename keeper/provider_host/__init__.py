"""Per-user Keeper Provider Host contracts.

The host is an execution deputy.  KeeperAuthority remains the sole source of
provider registration, qualification, reservation, usage, and launch policy.
"""

from keeper.provider_host.protocol import HOST_PROTOCOL


HOST_VERSION = "1.0.0"

__all__ = ["HOST_PROTOCOL", "HOST_VERSION"]
