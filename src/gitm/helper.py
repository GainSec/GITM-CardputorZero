"""Root-owned, fixed-action helper for package-specific network state."""

import argparse
from dataclasses import asdict, dataclass
from enum import Enum, auto
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
from typing import Callable, Mapping, Sequence

from .discovery import discover_interfaces
from .model import InterfaceDiscovery
from .plan import AP_SURFACE, NFT_TABLE, OperationPlan, RUNTIME_DIR, build_plan
from .validation import ValidationError, validate_config


class HelperError(RuntimeError):
    pass


class FatalChildCleanup(SystemExit):
    """Force systemd to tear down the helper cgroup after unproven child exit."""


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start_time: int
    comm: str
    executable: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ProcessIdentity":
        return cls(int(value["pid"]), int(value["start_time"]), str(value["comm"]), str(value["executable"]))


CommandRunner = Callable[[Sequence[str]], object]
ProcessSpawner = Callable[[Sequence[str]], subprocess.Popen[bytes]]
TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
TERMINATION_SIGNALS = frozenset({signal.SIGTERM, signal.SIGINT})


def _run(argv: Sequence[str]) -> None:
    subprocess.run(
        list(argv), check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, env={**os.environ, "PATH": TRUSTED_TOOL_PATH},
    )


def _unblock_child_termination_signals() -> None:
    # The helper service is deliberately single-threaded. Keep this pre-exec
    # callback to one async-signal-safe pthread_sigmask operation: Python warns
    # that lock-taking preexec_fn callbacks can deadlock in threaded parents.
    signal.pthread_sigmask(signal.SIG_UNBLOCK, TERMINATION_SIGNALS)


def _spawn(argv: Sequence[str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, env={**os.environ, "PATH": TRUSTED_TOOL_PATH},
        preexec_fn=_unblock_child_termination_signals,
    )


class StateKind(Enum):
    ABSENT = auto()
    VALID_OWNED = auto()
    FOREIGN = auto()
    CORRUPT = auto()


@dataclass(frozen=True)
class StateLoad:
    kind: StateKind
    state: dict[str, object] | None = None
    error: str | None = None


def _live_evidence() -> InterfaceDiscovery:
    environment = {**os.environ, "PATH": TRUSTED_TOOL_PATH}

    def output(argv: Sequence[str]) -> str:
        return subprocess.run(
            list(argv), check=True, capture_output=True, text=True,
            stdin=subprocess.DEVNULL, env=environment,
        ).stdout

    links = output(("ip", "-d", "-json", "link", "show"))
    names = {
        item["ifname"] for item in json.loads(links)
        if isinstance(item, dict) and isinstance(item.get("ifname"), str)
    }
    physical = {name for name in names if (Path("/sys/class/net") / name / "device").exists()}
    return discover_interfaces(
        links,
        output(("iw", "list")),
        output(("iw", "dev")),
        output(("ip", "-json", "address", "show")),
        physical_interfaces=physical,
    )


def _process_identity(pid: int, *, proc_root: Path = Path("/proc")) -> ProcessIdentity | None:
    try:
        process_root = proc_root / str(pid)
        stat = (process_root / "stat").read_text(encoding="ascii")
        _prefix, separator, fields = stat.rpartition(") ")
        if not separator:
            return None
        start_time = int(fields.split()[19])
        comm = (process_root / "comm").read_text(encoding="utf-8").strip()
        try:
            executable = os.readlink(process_root / "exe")
        except PermissionError:
            # dnsmasq drops UID/GID after opening its sockets. Under the
            # service capability boundary that makes /proc/<pid>/exe
            # unreadable, while cmdline remains readable. PID + kernel start
            # time still prevents PID-reuse substitution; resolve argv[0]
            # only to recover the executable path captured before the drop.
            argv0 = (process_root / "cmdline").read_bytes().split(b"\0", 1)[0]
            if not argv0:
                return None
            command = os.fsdecode(argv0)
            resolved = command if os.path.isabs(command) else shutil.which(command, path=TRUSTED_TOOL_PATH)
            if not resolved:
                return None
            executable = os.path.realpath(resolved)
        return ProcessIdentity(pid, start_time, comm, executable)
    except (OSError, ValueError, IndexError):
        return None


def _probe_command(argv: Sequence[str]) -> bool:
    try:
        result = subprocess.run(
            list(argv),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, "PATH": TRUSTED_TOOL_PATH},
        )
    except FileNotFoundError:
        return False
    return result.returncode == 0


def probe_owned_resources(probe: Callable[[Sequence[str]], bool] = _probe_command) -> tuple[str, ...]:
    occupied = []
    if probe(("ip", "link", "show", AP_SURFACE)):
        occupied.append(f"AP surface {AP_SURFACE} already exists")
    if probe(("nft", "list", "table", "inet", NFT_TABLE)):
        occupied.append(f"nftables table {NFT_TABLE} already exists")
    return tuple(occupied)


def probe_resource_liveness(probe: Callable[[Sequence[str]], bool] = _probe_command) -> dict[str, bool]:
    return {
        AP_SURFACE: probe(("ip", "link", "show", AP_SURFACE)),
        NFT_TABLE: probe(("nft", "list", "table", "inet", NFT_TABLE)),
    }


def validate_plan_for_helper(plan: OperationPlan) -> OperationPlan:
    canonical = build_plan(plan.config)
    if plan.to_dict() != canonical.to_dict():
        raise HelperError("plan does not match the validated package plan")
    return plan


class BoundedLog:
    def __init__(self, path: Path, max_bytes: int = 256 * 1024, backups: int = 3):
        self.path = path
        self.max_bytes = max_bytes
        self.backups = backups

    def write(self, message: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
            oldest = self.path.with_name(f"{self.path.name}.{self.backups}")
            oldest.unlink(missing_ok=True)
            for number in range(self.backups - 1, 0, -1):
                source = self.path.with_name(f"{self.path.name}.{number}")
                if source.exists():
                    source.replace(self.path.with_name(f"{self.path.name}.{number + 1}"))
            self.path.replace(self.path.with_name(f"{self.path.name}.1"))
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(descriptor, (message.rstrip() + "\n").encode("utf-8", "replace"))
        finally:
            os.close(descriptor)


class HelperEngine:
    def __init__(
        self,
        *,
        runtime_dir: Path = Path(RUNTIME_DIR),
        forwarding_path: Path = Path("/proc/sys/net/ipv4/ip_forward"),
        runner: CommandRunner = _run,
        spawner: ProcessSpawner = _spawn,
        identity_provider: Callable[[int], ProcessIdentity | None] = _process_identity,
        killer: Callable[[int, int], None] = os.kill,
        resource_probe: Callable[[], Sequence[str]] | None = None,
        resource_liveness: Callable[[], Mapping[str, bool]] | None = None,
        evidence_provider: Callable[[], InterfaceDiscovery] | None = None,
        sleeper: Callable[[float], None] | None = None,
        wait_attempts: int = 10,
        stabilization_interval: float = 0.5,
        child_cleanup_timeout: float = 0.5,
        log: BoundedLog | None = None,
        signal_masker: Callable[[int, object], object] | None = None,
        transition_hook: Callable[[str, str | None], None] | None = None,
    ):
        self.runtime_dir = runtime_dir
        self.forwarding_path = forwarding_path
        self.runner = runner
        self.spawner = spawner
        self._children: dict[int, object] = {}
        self.identity_provider = identity_provider
        self.killer = killer
        self.resource_probe = (
            resource_probe
            if resource_probe is not None
            else (probe_owned_resources if runner is _run else lambda: ())
        )
        self.evidence_provider = evidence_provider or (
            _live_evidence if runner is _run else
            lambda: InterfaceDiscovery(("wlan1",), ("enp2s0",))
        )
        self.resource_liveness = resource_liveness or (
            probe_resource_liveness if runner is _run else
            lambda: {AP_SURFACE: True, NFT_TABLE: True}
        )
        if sleeper is None:
            import time
            sleeper = time.sleep
        self.sleeper = sleeper
        self.wait_attempts = wait_attempts
        self.stabilization_interval = stabilization_interval
        self.child_cleanup_timeout = child_cleanup_timeout
        self.signal_masker = signal_masker if signal_masker is not None else getattr(signal, "pthread_sigmask", None)
        self.transition_hook = transition_hook or (lambda _point, _name: None)
        if log is not None:
            self.log = log
        elif runtime_dir == Path(RUNTIME_DIR):
            self.log = BoundedLog(Path("/var/log/gainsec-gitm/events.log"))
        else:
            self.log = BoundedLog(runtime_dir.parent / "events.log")
        self.state_path = runtime_dir / "state.json"

    def _write_private(self, path: Path, content: str) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(descriptor, content.encode())
        finally:
            os.close(descriptor)

    def _save_state(self, state: Mapping[str, object]) -> None:
        temporary = self.state_path.with_suffix(".json.tmp")
        self._write_private(temporary, json.dumps(state, sort_keys=True))
        temporary.replace(self.state_path)

    def _load_state(self) -> StateLoad:
        try:
            raw = self.state_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return StateLoad(StateKind.ABSENT)
        except OSError as exc:
            return StateLoad(StateKind.CORRUPT, error=f"state is unreadable: {exc}")
        try:
            state = json.loads(raw)
        except json.JSONDecodeError as exc:
            return StateLoad(StateKind.CORRUPT, error=f"state is malformed: {exc.msg}")
        if not isinstance(state, dict):
            return StateLoad(StateKind.CORRUPT, error="state root is not an object")
        if self._is_owned_state(state):
            return StateLoad(StateKind.VALID_OWNED, state)
        owner = state.get("owner")
        if owner == "gainsec-gitm":
            return StateLoad(StateKind.CORRUPT, error="package-owned state schema is invalid")
        if isinstance(owner, str) and owner:
            return StateLoad(StateKind.FOREIGN, state, "state belongs to a foreign owner")
        return StateLoad(StateKind.CORRUPT, error="state owner is missing or invalid")

    @staticmethod
    def _is_owned_state(state: Mapping[str, object]) -> bool:
        if not (
            state.get("owner") == "gainsec-gitm"
            and state.get("state") in {"starting", "active", "stopping", "cleanup_failed"}
            and state.get("resources") == [AP_SURFACE, NFT_TABLE]
            and state.get("previous_ipv4_forwarding") in {"0", "1"}
        ):
            return False
        processes = state.get("processes", {})
        if not isinstance(processes, Mapping):
            return False
        for name, raw in processes.items():
            if name not in {"dnsmasq", "hostapd"} or not isinstance(raw, Mapping):
                return False
            if set(raw) != {"pid", "start_time", "comm", "executable"}:
                return False
            if (
                not isinstance(raw.get("pid"), int) or isinstance(raw.get("pid"), bool)
                or int(raw["pid"]) <= 1
                or not isinstance(raw.get("start_time"), int) or isinstance(raw.get("start_time"), bool)
                or int(raw["start_time"]) < 0
                or not isinstance(raw.get("comm"), str) or not raw["comm"]
                or not isinstance(raw.get("executable"), str) or not raw["executable"]
            ):
                return False
        launches = state.get("launches", {})
        if not isinstance(launches, Mapping):
            return False
        for name, raw in launches.items():
            if name not in {"dnsmasq", "hostapd"} or not isinstance(raw, Mapping):
                return False
            if raw.get("status") not in {"intent", "spawn_failed", "identified"}:
                return False
            argv = raw.get("argv")
            if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
                return False
        progress = state.get("cleanup_progress", {})
        if not isinstance(progress, Mapping) or not all(isinstance(key, str) and isinstance(value, bool) for key, value in progress.items()):
            return False
        cleanup_errors = state.get("cleanup_errors", [])
        return isinstance(cleanup_errors, list) and all(isinstance(item, str) for item in cleanup_errors)

    def _launch_process(self, name: str, argv: Sequence[str], state: dict[str, object]) -> ProcessIdentity:
        launches = state.setdefault("launches", {})
        processes = state.setdefault("processes", {})
        if not isinstance(launches, dict) or not isinstance(processes, dict):
            raise HelperError("process launch state is invalid")
        launches[name] = {"status": "intent", "argv": list(argv)}
        self._save_state(state)
        self.transition_hook("launch_intent_saved", name)

        old_mask = None
        child = None
        if self.signal_masker is not None:
            old_mask = self.signal_masker(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        try:
            child = self.spawner(argv)
            self._children[child.pid] = child
            if child.pid <= 1:
                raise HelperError(f"{name} returned unsafe child PID")
            self.transition_hook("child_spawned", name)
            identity = None
            for attempt in range(self.wait_attempts):
                candidate = self.identity_provider(child.pid)
                if (
                    candidate is not None
                    and candidate.pid == child.pid
                    and candidate.comm == name
                    and Path(candidate.executable).name == name
                ):
                    identity = candidate
                    break
                if attempt + 1 < self.wait_attempts:
                    self.sleeper(0.05)
            if identity is None:
                raise HelperError(f"{name} child is not live with expected identity after launch")
            self.transition_hook("identity_captured", name)
            candidate_state = dict(state)
            candidate_processes = dict(processes)
            candidate_launches = dict(launches)
            candidate_processes[name] = identity.to_dict()
            candidate_launches[name] = {"status": "identified", "argv": list(argv)}
            candidate_state["processes"] = candidate_processes
            candidate_state["launches"] = candidate_launches
            self._save_state(candidate_state)
            state.clear()
            state.update(candidate_state)
            self.transition_hook("identity_saved", name)
            return identity
        except BaseException:
            if child is None:
                launches[name] = {"status": "spawn_failed", "argv": list(argv)}
                try:
                    self._save_state(state)
                except Exception:
                    pass
            else:
                self._cleanup_direct_child(child)
                processes.pop(name, None)
                launches[name] = {"status": "spawn_failed", "argv": list(argv)}
            raise
        finally:
            if self.signal_masker is not None:
                self.signal_masker(signal.SIG_SETMASK, old_mask if old_mask is not None else frozenset())

    def _cleanup_direct_child(self, child: subprocess.Popen[bytes]) -> None:
        """Terminate and reap a retained direct child without trusting /proc identity."""
        pid = child.pid
        reaped = False
        try:
            try:
                child.terminate()
            except Exception:
                # A failed SIGTERM does not skip the mandatory wait/escalation.
                pass
            try:
                child.wait(timeout=self.child_cleanup_timeout)
                reaped = True
            except Exception:
                try:
                    child.kill()
                except Exception:
                    pass
                try:
                    child.wait(timeout=self.child_cleanup_timeout)
                    reaped = True
                except Exception:
                    pass
        finally:
            self._children.pop(pid, None)
        if not reaped:
            raise FatalChildCleanup(f"cannot prove direct child exit for PID {pid}")

    def _liveness_errors(self, state: Mapping[str, object]) -> list[str]:
        errors = []
        processes = state.get("processes", {})
        if not isinstance(processes, Mapping):
            return ["owned process identity evidence missing"]
        for name in ("hostapd", "dnsmasq"):
            raw = processes.get(name)
            if not isinstance(raw, Mapping):
                errors.append(f"{name} identity missing")
                continue
            try:
                expected = ProcessIdentity.from_dict(raw)
            except (KeyError, TypeError, ValueError):
                errors.append(f"{name} identity is invalid")
                continue
            self._reap_child(expected.pid)
            if self.identity_provider(expected.pid) != expected:
                errors.append(f"{name} identity is not live")
        live_resources = self.resource_liveness()
        for resource in (AP_SURFACE, NFT_TABLE):
            if not live_resources.get(resource, False):
                errors.append(f"owned resource {resource} is not live")
        return errors

    def _reap_child(self, pid: int) -> None:
        child = self._children.get(pid)
        if child is None:
            return
        poll = getattr(child, "poll", None)
        if callable(poll) and poll() is not None:
            self._children.pop(pid, None)

    def _stop_owned_processes(self, state: dict[str, object]) -> list[str]:
        errors = []
        progress = state.setdefault("cleanup_progress", {})
        processes = state.get("processes", {})
        if not isinstance(processes, Mapping) or not isinstance(progress, dict):
            return errors
        for name in ("hostapd", "dnsmasq"):
            key = f"process:{name}"
            if progress.get(key):
                continue
            raw = processes.get(name)
            launches = state.get("launches", {})
            launch = launches.get(name) if isinstance(launches, Mapping) else None
            if not isinstance(raw, Mapping):
                if isinstance(launch, Mapping) and launch.get("status") != "spawn_failed":
                    errors.append(f"stop {name}: complete persisted process identity is missing; recovery required")
                else:
                    progress[key] = True
                continue
            try:
                expected = ProcessIdentity.from_dict(raw)
            except (KeyError, TypeError, ValueError):
                errors.append(f"stop {name}: process identity evidence is invalid")
                continue
            self._reap_child(expected.pid)
            current = self.identity_provider(expected.pid)
            if current is None:
                child = self._children.get(expected.pid)
                if child is not None:
                    self._cleanup_direct_child(child)
                progress[key] = True
                continue
            if current != expected:
                errors.append(f"stop {name}: process identity mismatch")
                continue
            try:
                self.killer(expected.pid, signal.SIGTERM)
            except ProcessLookupError:
                progress[key] = True
                continue
            except OSError as exc:
                errors.append(f"stop {name}: {exc}")
                continue
            for _attempt in range(self.wait_attempts):
                self._reap_child(expected.pid)
                current = self.identity_provider(expected.pid)
                if current != expected:
                    child = self._children.get(expected.pid)
                    if child is not None:
                        self._cleanup_direct_child(child)
                    progress[key] = True
                    break
                self.sleeper(0.05)
            else:
                try:
                    self.killer(expected.pid, signal.SIGKILL)
                except ProcessLookupError:
                    progress[key] = True
                    continue
                except OSError as exc:
                    errors.append(f"kill {name}: {exc}")
                    continue
                for _attempt in range(self.wait_attempts):
                    self._reap_child(expected.pid)
                    current = self.identity_provider(expected.pid)
                    if current != expected:
                        child = self._children.get(expected.pid)
                        if child is not None:
                            self._cleanup_direct_child(child)
                        progress[key] = True
                        break
                    self.sleeper(0.05)
                else:
                    errors.append(f"stop {name}: process remains live")
        return errors

    def _cleanup_owned_network(self, state: dict[str, object]) -> list[str]:
        errors = []
        progress = state.setdefault("cleanup_progress", {})
        for key, resource, argv in (
            ("resource:nft", NFT_TABLE, ("nft", "delete", "table", "inet", NFT_TABLE)),
            ("resource:ap", AP_SURFACE, ("iw", "dev", AP_SURFACE, "del")),
        ):
            if isinstance(progress, dict) and progress.get(key):
                continue
            try:
                if not self.resource_liveness().get(resource, False):
                    if isinstance(progress, dict):
                        progress[key] = True
                    continue
                self.runner(argv)
                if self.resource_liveness().get(resource, False):
                    errors.append(f"{' '.join(argv[:2])}: resource remains live")
                elif isinstance(progress, dict):
                    progress[key] = True
            except Exception as exc:
                errors.append(f"{' '.join(argv[:2])}: {exc}")
        return errors

    def _restore_forwarding(self, previous: str | None) -> None:
        if previous in {"0", "1"}:
            self.forwarding_path.write_text(previous + "\n", encoding="ascii")

    def _remove_private_state(self) -> list[str]:
        errors = []
        for name in (
            "hostapd.conf",
            "dnsmasq.conf",
            "nftables.conf",
            "hostapd.pid",
            "dnsmasq.pid",
            "dnsmasq.leases",
            "dnsmasq.log",
        ):
            try:
                (self.runtime_dir / name).unlink(missing_ok=True)
            except OSError as exc:
                errors.append(f"remove {name}: {exc}")
        if errors:
            return errors
        for name in ("state.json.tmp", "state.json"):
            try:
                (self.runtime_dir / name).unlink(missing_ok=True)
            except OSError as exc:
                errors.append(f"remove {name}: {exc}")
                break
        return errors

    def _safe_log(self, message: str) -> list[str]:
        try:
            self.log.write(message)
            return []
        except OSError as exc:
            return [f"log: {exc}"]

    def _rollback(self, previous: str | None, message: str, state: dict[str, object] | None = None, force_retain: bool = False) -> list[str]:
        state = state or {
            "state": "cleanup_failed", "owner": "gainsec-gitm",
            "resources": [AP_SURFACE, NFT_TABLE], "previous_ipv4_forwarding": previous,
            "processes": {},
        }
        errors = []
        try:
            errors.extend(self._stop_owned_processes(state))
        except Exception as exc:
            errors.append(f"process cleanup: {exc}")
        errors.extend(self._cleanup_owned_network(state))
        progress = state.setdefault("cleanup_progress", {})
        if not isinstance(progress, dict):
            errors.append("cleanup progress is invalid")
        elif not progress.get("forwarding"):
            try:
                self._restore_forwarding(previous)
                progress["forwarding"] = True
            except OSError as exc:
                errors.append(f"forwarding restore: {exc}")
        errors.extend(self._safe_log(message))
        if errors or force_retain:
            state["state"] = "cleanup_failed"
            state["cleanup_errors"] = list(errors or ["cleanup state persistence failed; retry required"])
            try:
                self._save_state(state)
            except Exception as exc:
                errors.append(f"retain cleanup state: {exc}")
            return errors
        removal_errors = self._remove_private_state()
        if removal_errors:
            errors.extend(removal_errors)
            state["state"] = "cleanup_failed"
            state["cleanup_errors"] = list(removal_errors)
            try:
                self._save_state(state)
            except Exception as exc:
                errors.append(f"retain cleanup state: {exc}")
        return errors

    def start(self, plan: OperationPlan) -> dict[str, object]:
        plan = validate_plan_for_helper(plan)
        loaded = self._load_state()
        if loaded.kind is StateKind.VALID_OWNED:
            raise HelperError("owned session state exists; successful stop/recovery required before start")
        if loaded.kind is StateKind.CORRUPT:
            raise HelperError(f"state recovery required; refusing to overwrite corrupt state: {loaded.error}")
        if loaded.kind is StateKind.FOREIGN:
            raise HelperError("state recovery required; refusing to overwrite foreign state")
        try:
            evidence = self.evidence_provider()
            if plan.config.ap_interface not in evidence.ap_interfaces:
                raise HelperError(f"selected AP interface {plan.config.ap_interface} is not currently AP-capable")
            if plan.config.wan_interface not in evidence.wan_interfaces:
                raise HelperError(f"selected WAN interface {plan.config.wan_interface} is not linked physical Ethernet")
            validate_config(plan.config, evidence.existing_networks)
        except ValidationError as exc:
            raise HelperError(str(exc)) from exc
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as exc:
            raise HelperError(f"live interface discovery failed: {exc}") from exc
        occupied = tuple(self.resource_probe())
        if occupied:
            raise HelperError("required resource occupied: " + "; ".join(occupied))
        try:
            previous = self.forwarding_path.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise HelperError(f"cannot read IPv4 forwarding state: {exc}") from exc
        if previous not in {"0", "1"}:
            raise HelperError("invalid IPv4 forwarding state")
        state = {
            "state": "starting",
            "owner": "gainsec-gitm",
            "resources": [AP_SURFACE, NFT_TABLE],
            "previous_ipv4_forwarding": previous,
        }
        try:
            self.runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.runtime_dir.chmod(0o700)
            for source_path, content in plan.files.items():
                self._write_private(self.runtime_dir / Path(source_path).name, content)
            self._save_state(state)
        except Exception as exc:
            cleanup_errors = self._remove_private_state()
            cleanup_errors.extend(self._safe_log(f"start preparation failed: {type(exc).__name__}"))
            detail = f"prepare failed: {exc}"
            if cleanup_errors:
                detail += "; cleanup: " + "; ".join(cleanup_errors)
            raise HelperError(detail) from exc
        try:
            self.forwarding_path.write_text("1\n", encoding="ascii")
            for action in plan.actions:
                if action.name in {"start_dnsmasq", "start_hostapd"}:
                    self._launch_process(action.name.removeprefix("start_"), action.argv, state)
                else:
                    self.runner(action.argv)
            self.sleeper(self.stabilization_interval)
            liveness_errors = self._liveness_errors(state)
            if liveness_errors:
                raise HelperError("; ".join(liveness_errors))
            state["state"] = "active"
            self._save_state(state)
            self.transition_hook("active_saved", None)
            self.log.write("AP session started")
            return {"ok": True, "state": "active"}
        except Exception as exc:
            cleanup_errors = self._rollback(previous, f"start failed and rolled back: {type(exc).__name__}", state)
            detail = f"start failed and rolled back: {exc}"
            if cleanup_errors:
                detail += "; cleanup: " + "; ".join(cleanup_errors)
            raise HelperError(detail) from exc

    def stop(self) -> dict[str, object]:
        loaded = self._load_state()
        if loaded.kind is StateKind.ABSENT:
            return {"ok": True, "state": "inactive"}
        if loaded.kind is StateKind.CORRUPT:
            raise HelperError(f"state recovery required; corrupt state was not modified: {loaded.error}")
        if loaded.kind is StateKind.FOREIGN:
            raise HelperError("foreign state recovery required; state was not modified")
        assert loaded.state is not None
        state = loaded.state
        state["state"] = "stopping"
        errors = []
        try:
            self._save_state(state)
        except Exception as exc:
            errors.append(f"save stopping state: {exc}")
        errors.extend(self._rollback(state.get("previous_ipv4_forwarding"), "owned AP session stopped", state, force_retain=bool(errors)))
        if errors:
            raise HelperError("cleanup failed: " + "; ".join(errors))
        return {"ok": True, "state": "inactive"}

    def status(self) -> dict[str, object]:
        loaded = self._load_state()
        if loaded.kind is StateKind.CORRUPT:
            return {"ok": False, "state": "blocked", "backend": "system", "errors": [f"state recovery required: {loaded.error}"]}
        if loaded.kind is StateKind.FOREIGN:
            return {"ok": False, "state": "blocked", "backend": "system", "errors": ["foreign state recovery required"]}
        if loaded.kind is StateKind.VALID_OWNED:
            assert loaded.state is not None
            owned = loaded.state
            if owned.get("state") == "cleanup_failed":
                return {"ok": False, "state": "blocked", "backend": "system", "errors": list(owned.get("cleanup_errors", ["cleanup retry required"]))}
            errors = self._liveness_errors(owned)
            if errors:
                return {"ok": False, "state": "blocked", "backend": "system", "errors": errors}
            return {"ok": True, "state": str(owned["state"]), "backend": "system"}
        occupied = tuple(self.resource_probe())
        if occupied:
            return {"ok": False, "state": "blocked", "backend": "system", "errors": list(occupied)}
        return {"ok": True, "state": "inactive", "backend": "system"}

    def dispatch(self, request: Mapping[str, object]) -> dict[str, object]:
        action = request.get("action")
        if action == "status":
            return self.status()
        if action == "stop":
            return self.stop()
        if action == "start":
            raw_plan = request.get("plan")
            if not isinstance(raw_plan, Mapping):
                raise HelperError("start requires a plan")
            return self.start(OperationPlan.from_dict(raw_plan))
        raise HelperError("unknown action")

    def handle_signal(self, _signum, _frame) -> None:
        try:
            self.stop()
        finally:
            raise SystemExit(128 + int(_signum))


def _handle_connection(connection: socket.socket, engine: HelperEngine, timeout: float = 1.0) -> None:
    connection.settimeout(timeout)
    try:
        line = connection.makefile("rb").readline(1_048_576)
        if not line or len(line) >= 1_048_576 or not line.endswith(b"\n"):
            raise HelperError("invalid request size or framing")
        request = json.loads(line)
        response = engine.dispatch(request)
    except socket.timeout:
        response = {"ok": False, "error": "request timed out"}
    except Exception as exc:
        response = {"ok": False, "error": str(exc)[:200]}
    connection.sendall(json.dumps(response, sort_keys=True).encode() + b"\n")


def _serve() -> int:
    if os.geteuid() != 0:
        raise HelperError("helper must run as root")
    engine = HelperEngine()
    signal.signal(signal.SIGTERM, engine.handle_signal)
    signal.signal(signal.SIGINT, engine.handle_signal)
    listener = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
    while True:
        connection, _address = listener.accept()
        with connection:
            try:
                _handle_connection(connection, engine)
            except OSError:
                continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gainsec-gitm-helper")
    parser.add_argument("action", choices=("serve", "stop"))
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        raise HelperError("helper must run as root")
    if args.action == "serve":
        return _serve()
    HelperEngine().stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
