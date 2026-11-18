"""Deterministic off-device backend."""

from ..certificates import generate_local_ca
from ..configuration import load_ca_material
from ..model import InterfaceDiscovery
from ..plan import OperationPlan
from .base import PreflightReport


class SimBackend:
    name = "sim"

    def __init__(self, seed: int = 0):
        self.seed = seed
        self._active = False
        self._plan = None
        self._ca = None

    def discovery(self) -> InterfaceDiscovery:
        return InterfaceDiscovery(
            ap_interfaces=("wlan1",),
            wan_interfaces=("enp2s0",),
            evidence={"wlan1": "phy0 supports AP", "enp2s0": "Ethernet carrier present"},
        )

    def preflight(self) -> PreflightReport:
        return PreflightReport(ok=True)

    def start(self, plan: OperationPlan) -> dict[str, object]:
        load_ca_material(plan.config)
        self._plan = plan
        self._active = True
        return self.status()

    def stop(self) -> dict[str, object]:
        self._active = False
        return {"ok": True, "state": "inactive", "backend": self.name}

    def status(self) -> dict[str, object]:
        config = self._plan.config if self._plan else None
        return {"ok": True, "state": "active" if self._active else "inactive", "backend": self.name,
                "simulated": True, "features": {"capture": bool(config and config.capture), "live": bool(config and config.live), "tls": bool(config and config.tls), "leases": bool(config and config.lease_events)},
                "evidence": dict(self._plan.evidence_paths) if self._plan else {},
                "note": "simulation only; no hardware processes or capture files created"}

    def ca_material(self, config):
        material = load_ca_material(config)
        if material is not None:
            return material
        if self._ca is None:
            self._ca = generate_local_ca()
        return self._ca

    def inspect(self, *, kind="live", limit=20):
        return {"ok": True, "simulated": True, "events": [], "kind": kind, "evidence": self.status()["evidence"]}
