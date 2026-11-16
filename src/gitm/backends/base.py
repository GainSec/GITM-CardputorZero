"""Backend protocol and fail-closed result models."""

from dataclasses import dataclass
from typing import Protocol

from ..model import InterfaceDiscovery
from ..plan import OperationPlan


class BackendUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class PreflightReport:
    ok: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {"ok": self.ok, "errors": list(self.errors), "warnings": list(self.warnings)}


class Backend(Protocol):
    name: str

    def discovery(self) -> InterfaceDiscovery: ...
    def preflight(self) -> PreflightReport: ...
    def start(self, plan: OperationPlan) -> dict[str, object]: ...
    def stop(self) -> dict[str, object]: ...
    def status(self) -> dict[str, object]: ...
