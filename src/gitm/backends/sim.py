"""Deterministic off-device backend."""

from ..model import InterfaceDiscovery
from ..plan import OperationPlan
from .base import PreflightReport


class SimBackend:
    name = "sim"

    def __init__(self, seed: int = 0):
        self.seed = seed
        self._active = False

    def discovery(self) -> InterfaceDiscovery:
        return InterfaceDiscovery(
            ap_interfaces=("wlan1",),
            wan_interfaces=("enp2s0",),
            evidence={"wlan1": "phy0 supports AP", "enp2s0": "Ethernet carrier present"},
        )

    def preflight(self) -> PreflightReport:
        return PreflightReport(ok=True)

    def start(self, plan: OperationPlan) -> dict[str, object]:
        self._active = True
        return {"ok": True, "state": "active", "backend": self.name}

    def stop(self) -> dict[str, object]:
        self._active = False
        return {"ok": True, "state": "inactive", "backend": self.name}

    def status(self) -> dict[str, object]:
        return {"ok": True, "state": "active" if self._active else "inactive", "backend": self.name}
