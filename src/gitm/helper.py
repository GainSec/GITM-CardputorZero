"""Root-owned, fixed-action helper for package-specific network state."""

import argparse
from dataclasses import asdict, dataclass
from enum import Enum, auto
from ipaddress import ip_network
import json
import os
from pathlib import Path
import shutil
import resource
import pwd
import struct
import signal
import socket
import subprocess
from typing import Callable, Mapping, Sequence

from .certificates import CAMaterial, atomic_private, ensure_local_ca, validate_material
from .profiles import verify_profile
from .discovery import discover_interfaces
from .model import InterfaceDiscovery, NetworkConfig
from .plan import AP_SURFACE, NFT_TABLE, OperationPlan, RUNTIME_DIR, DATA_DIR, LEASE_DIR, build_plan
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
    setup = _unblock_child_termination_signals
    if argv[0] in {"sslsplit", "tcpdump"}:
        limit = 512 * 1024 if argv[0] == "sslsplit" else (int(argv[argv.index("-C") + 1]) * 1_000_000 + 1_000_000)
        def setup():
            _unblock_child_termination_signals()
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    return subprocess.Popen(
        list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, env={**os.environ, "PATH": TRUSTED_TOOL_PATH},
        preexec_fn=setup,
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


def _owned_proxy_children(identity: ProcessIdentity, *, proc_root: Path = Path("/proc")) -> tuple[ProcessIdentity, ...]:
    """Kernel-proven direct SSLsplit descendants, never a process-name search."""
    if _process_identity(identity.pid, proc_root=proc_root) != identity:
        return ()
    try:
        raw = (proc_root / str(identity.pid) / "task" / str(identity.pid) / "children").read_text(encoding="ascii")
        pids = [int(value) for value in raw.split()]
        if len(pids) > 8:
            return ()
        children = []
        for pid in pids:
            candidate = _process_identity(pid, proc_root=proc_root)
            stat = (proc_root / str(pid) / "stat").read_text(encoding="ascii").rpartition(") ")[2].split()
            if (candidate is not None and int(stat[1]) == identity.pid
                    and candidate.comm == "sslsplit" and candidate.executable == identity.executable
                    and candidate.start_time >= identity.start_time):
                children.append(candidate)
        if _process_identity(identity.pid, proc_root=proc_root) == identity:
            return tuple(children)
    except (OSError, ValueError, IndexError):
        pass
    return ()


def _owned_listener(identity: ProcessIdentity, address: str, *, proc_root: Path = Path("/proc"), include_proxy: bool = True) -> bool:
    """Prove the supervisor or its kernel-proven proxy owns the TLS socket."""
    if include_proxy and any(_owned_listener(child, address, proc_root=proc_root, include_proxy=False) for child in _owned_proxy_children(identity, proc_root=proc_root)):
        return True
    root = proc_root / str(identity.pid)
    try:
        inodes = set()
        for entry in (root / "fd").iterdir():
            try:
                link = os.readlink(entry)
            except OSError:
                continue
            if link.startswith("socket:[") and link.endswith("]"):
                inodes.add(link[8:-1])
        local = socket.inet_aton(address)[::-1].hex().upper() + ":20FB"
        for line in (root / "net/tcp").read_text(encoding="ascii").splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 10 and fields[1] == local and fields[3] == "0A" and fields[9] in inodes:
                return True
    except (OSError, ValueError):
        return False
    return False


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
        data_dir: Path = Path(DATA_DIR),
        forwarding_path: Path = Path("/proc/sys/net/ipv4/ip_forward"),
        runner: CommandRunner = _run,
        spawner: ProcessSpawner = _spawn,
        identity_provider: Callable[[int], ProcessIdentity | None] = _process_identity,
        killer: Callable[[int, int], None] = os.kill,
        resource_probe: Callable[[], Sequence[str]] | None = None,
        resource_liveness: Callable[[], Mapping[str, bool]] | None = None,
        listener_probe: Callable[[ProcessIdentity, str], bool] | None = None,
        proxy_children: Callable[[ProcessIdentity], Sequence[ProcessIdentity]] | None = None,
        evidence_provider: Callable[[], InterfaceDiscovery] | None = None,
        sleeper: Callable[[float], None] | None = None,
        wait_attempts: int = 10,
        proxy_wait_attempts: int = 200,
        startup_wait_attempts: int = 200,
        stabilization_interval: float = 0.5,
        child_cleanup_timeout: float = 0.5,
        log: BoundedLog | None = None,
        signal_masker: Callable[[int, object], object] | None = None,
        transition_hook: Callable[[str, str | None], None] | None = None,
    ):
        self.runtime_dir = runtime_dir
        self.data_dir = data_dir
        self.lease_dir = runtime_dir.parent / "leases"
        self.forwarding_path = forwarding_path
        self.runner = runner
        self.spawner = spawner
        self._children: dict[int, object] = {}
        self.identity_provider = identity_provider
        self._require_proxy = runner is _run or proxy_children is not None
        self.proxy_children = proxy_children or _owned_proxy_children
        self.listener_probe = listener_probe or (_owned_listener if runner is _run else lambda _identity, _address: True)
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
        self.proxy_wait_attempts = proxy_wait_attempts
        self.startup_wait_attempts = startup_wait_attempts
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
        self._last_failure: list[str] = []

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
        optional = state.get("optional_processes", [])
        if not isinstance(optional, list) or not all(isinstance(x, str) and x in {"tcpdump", "sslsplit", "sslsplit_worker", "live", "leases"} for x in optional) or len(optional) != len(set(optional)):
            return False
        processes = state.get("processes", {})
        if not isinstance(processes, Mapping):
            return False
        for name, raw in processes.items():
            if name not in {"dnsmasq", "hostapd", "tcpdump", "live", "leases", "sslsplit", "sslsplit_worker"} or not isinstance(raw, Mapping):
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
            if name not in {"dnsmasq", "hostapd", "tcpdump", "live", "leases", "sslsplit", "sslsplit_worker"} or not isinstance(raw, Mapping):
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
            for attempt in range(self.startup_wait_attempts):
                candidate = self.identity_provider(child.pid)
                if (
                    candidate is not None
                    and candidate.pid == child.pid
                    and candidate.comm == (f"gitm-{name}" if name in {"live", "leases"} else name)
                    and (candidate.executable in {os.path.realpath("/usr/bin/python3"), "/usr/bin/python3.11"} if name in {"live", "leases"} else Path(candidate.executable).name == name)
                ):
                    identity = candidate
                    break
                if attempt + 1 < self.startup_wait_attempts:
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
            if name == "sslsplit" and self._require_proxy:
                self._register_proxy(state)
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

    def _register_proxy(self, state: dict[str, object]) -> None:
        parent = ProcessIdentity.from_dict(state["processes"]["sslsplit"])
        candidates = ()
        for attempt in range(self.proxy_wait_attempts):
            candidates = tuple(self.proxy_children(parent))
            if len(candidates) == 1:
                break
            if attempt + 1 < self.proxy_wait_attempts:
                self.sleeper(0.05)
        if len(candidates) != 1:
            raise HelperError("sslsplit proxy identity missing or ambiguous")
        state["processes"]["sslsplit_worker"] = candidates[0].to_dict()
        if "sslsplit_worker" not in state.setdefault("optional_processes", []):
            state["optional_processes"].append("sslsplit_worker")
        self._save_state(state)

    def _cleanup_direct_child(self, child: subprocess.Popen[bytes]) -> None:
        """Terminate and reap a retained direct child without trusting /proc identity."""
        pid = child.pid
        descendants = ()
        if self._require_proxy:
            try:
                identity = self.identity_provider(pid)
                if identity is not None and identity.comm == "sslsplit":
                    descendants = tuple(self.proxy_children(identity))
            except Exception:
                # Identity lookup failure must never prevent direct-child cleanup.
                pass
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
        if any(self.identity_provider(item.pid) == item for item in descendants):
            raise FatalChildCleanup("SSLsplit proxy exit is unproven; cgroup cleanup required")
        if not reaped:
            raise FatalChildCleanup(f"cannot prove direct child exit for PID {pid}")

    def _liveness_errors(self, state: Mapping[str, object]) -> list[str]:
        errors = []
        processes = state.get("processes", {})
        if not isinstance(processes, Mapping):
            return ["owned process identity evidence missing"]
        for name in ("hostapd", "dnsmasq", *state.get("optional_processes", [])):
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
            elif name == "sslsplit" and not self.listener_probe(expected, str(state.get("tls_address", ""))):
                errors.append("sslsplit owned TLS listener is not live")
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
        for name in ("live", "leases", "tcpdump", "sslsplit_worker", "sslsplit", "hostapd", "dnsmasq"):
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
        try:
            (self.lease_dir / "dnsmasq.leases").unlink(missing_ok=True)
            if self.lease_dir.exists():
                self.lease_dir.rmdir()
        except OSError as exc:
            errors.append(f"remove lease state: {exc}")
        for name in (
            "ca.crt",
            "ca.key",
            "chain.pem",
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

    def start(self, plan: OperationPlan, *, ca_material: CAMaterial | None = None) -> dict[str, object]:
        plan = validate_plan_for_helper(plan)
        if plan.config.profile:
            ca_material = verify_profile(plan.config.profile)
        elif ca_material is not None:
            ca_material = validate_material(ca_material.certificate, ca_material.private_key, ca_material.chain)
        elif plan.config.ca_cert:
            raise HelperError("validated custom CA material is required")
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
            "optional_processes": [a.name.removeprefix("start_") for a in plan.actions if a.name in {"start_tcpdump", "start_live", "start_leases", "start_sslsplit"}],
            "features": {"capture": plan.capture_enabled, "live": plan.config.live, "leases": plan.config.lease_events, "tls": plan.tls_interception_enabled},
            "evidence": {k: str(self.data_dir / Path(v).relative_to(DATA_DIR)) for k, v in plan.evidence_paths.items()},
            "owner_uid": plan.config.owner_uid,
            "tls_address": str(next(ip_network(plan.config.subnet).hosts())) if plan.config.tls else "",
            "state": "starting",
            "owner": "gainsec-gitm",
            "resources": [AP_SURFACE, NFT_TABLE],
            "previous_ipv4_forwarding": previous,
        }
        try:
            if plan.evidence_paths:
                target = self.data_dir / "users" / str(plan.config.owner_uid)
                target.mkdir(parents=True, exist_ok=True, mode=0o711)
                if shutil.disk_usage(target).free < (plan.config.capture_mb + 16) * 1_000_000:
                    raise HelperError("insufficient free disk space for capture/evidence")
                for output in state["evidence"].values():
                    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                    os.fchmod(descriptor, 0o600)
                    if os.geteuid() == 0:
                        os.fchown(descriptor, plan.config.owner_uid, -1)
                    os.close(descriptor)
            self.runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.runtime_dir.chmod(0o700)
            if plan.config.lease_events:
                self.lease_dir.mkdir(mode=0o700, exist_ok=True)
                self.lease_dir.chmod(0o700)
                if self.runner is _run:
                    account = pwd.getpwnam("dnsmasq")
                    os.chown(self.lease_dir, account.pw_uid, account.pw_gid)
            if plan.tls_interception_enabled:
                if ca_material is None:
                    ca_material = ensure_local_ca(self.data_dir / "ca" / str(plan.config.owner_uid))
                atomic_private(self.runtime_dir / "ca.crt", ca_material.certificate)
                atomic_private(self.runtime_dir / "ca.key", ca_material.private_key)
                if ca_material.chain:
                    atomic_private(self.runtime_dir / "chain.pem", ca_material.chain)
                public_cert = Path(state["evidence"]["certificate"])
                atomic_private(public_cert, ca_material.certificate)
                if os.geteuid() == 0:
                    os.chown(public_cert, plan.config.owner_uid, -1)
            for source_path, content in plan.files.items():
                self._write_private(self.runtime_dir / Path(source_path).name, content.replace(LEASE_DIR, str(self.lease_dir)))
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
                if action.name in {"start_dnsmasq", "start_hostapd", "start_tcpdump", "start_live", "start_leases", "start_sslsplit"}:
                    argv = tuple(arg.replace(DATA_DIR + "/", str(self.data_dir) + "/", 1) if arg.startswith(DATA_DIR + "/") else arg.replace(RUNTIME_DIR + "/", str(self.runtime_dir) + "/", 1) if arg.startswith(RUNTIME_DIR + "/") else arg.replace(LEASE_DIR + "/", str(self.lease_dir) + "/", 1) if arg.startswith(LEASE_DIR + "/") else arg for arg in action.argv)
                    self._launch_process(action.name.removeprefix("start_"), argv, state)
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
            return {"ok": True, "state": "active", "features": state["features"], "evidence": state["evidence"]}
        except Exception as exc:
            cleanup_errors = self._rollback(previous, f"start failed and rolled back: {type(exc).__name__}", state)
            detail = f"start failed and rolled back: {exc}"
            if cleanup_errors:
                detail += "; cleanup: " + "; ".join(cleanup_errors)
            raise HelperError(detail) from exc

    def stop(self) -> dict[str, object]:
        self._last_failure = []
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
            return {"ok": True, "state": str(owned["state"]), "backend": "system", "features": owned.get("features", {}), "evidence": owned.get("evidence", {})}
        occupied = tuple(self.resource_probe())
        if occupied:
            return {"ok": False, "state": "blocked", "backend": "system", "errors": list(occupied)}
        if self._last_failure:
            return {"ok": False, "state": "blocked", "backend": "system", "errors": self._last_failure}
        return {"ok": True, "state": "inactive", "backend": "system"}

    def watchdog(self) -> dict[str, object]:
        loaded = self._load_state()
        if loaded.kind is not StateKind.VALID_OWNED or loaded.state.get("state") != "active":
            return {"ok": True}
        errors = self._liveness_errors(loaded.state)
        evidence = loaded.state.get("evidence", {})
        if evidence:
            try:
                if shutil.disk_usage(self.data_dir).free < 16 * 1_000_000:
                    errors.append("evidence disk reserve exhausted")
            except OSError:
                errors.append("evidence storage unavailable")
        if errors:
            try:
                self.stop()
            except HelperError as exc:
                errors.append(str(exc))
            self._last_failure = errors
            self._safe_log("session stopped by liveness/storage watchdog")
            return {"ok": False, "errors": errors}
        return {"ok": True}

    def dispatch(self, request: Mapping[str, object], *, requester_uid: int | None = None) -> dict[str, object]:
        action = request.get("action")
        if action == "prepare-ca":
            config = NetworkConfig(**request["config"])
            validate_config(config)
            if requester_uid is not None and config.owner_uid != requester_uid:
                raise HelperError("CA owner must be the requesting user")
            if config.profile:
                material = verify_profile(config.profile)
            elif config.ca_cert:
                raw = request.get("ca_material")
                if not isinstance(raw, dict) or not all(isinstance(v, str) and len(v) <= 128 * 1024 for v in raw.values()):
                    raise HelperError("validated custom CA material is required")
                material = validate_material(raw.get("certificate", "").encode(), raw.get("private_key", "").encode(), raw.get("chain", "").encode())
            else:
                material = ensure_local_ca(self.data_dir / "ca" / str(config.owner_uid))
            return {"ok": True, "ca_material": {"certificate": material.certificate.decode(), "private_key": material.private_key.decode(), "chain": material.chain.decode(), "fingerprint": material.fingerprint, "trust_anchor": material.trust_anchor.decode()}}
        if action == "inspect":
            from .worker import read_events, safe_text
            kind = request.get("kind", "live")
            if kind not in {"live", "leases", "tls"}:
                raise HelperError("unknown evidence kind")
            uid = requester_uid if requester_uid is not None else os.getuid()
            path = self.data_dir / "users" / str(uid) / ("tls.log" if kind == "tls" else f"{kind}.jsonl")
            if kind == "tls":
                try:
                    with path.open("rb") as stream:
                        size = os.fstat(stream.fileno()).st_size
                        stream.seek(max(0, size - 16384))
                        events = [{"connection": safe_text(line.decode("utf-8", "replace"))} for line in stream.read(16384).splitlines()[-min(max(int(request.get("limit", 20)), 1), 100):]]
                except FileNotFoundError:
                    events = []
            else:
                events = read_events(path, limit=request.get("limit", 20))
            return {"ok": True, "kind": kind, "events": events, "path": str(path)}
        if action == "status":
            return self.status()
        if action == "stop":
            return self.stop()
        if action == "start":
            raw_plan = request.get("plan")
            if not isinstance(raw_plan, Mapping):
                raise HelperError("start requires a plan")
            plan = OperationPlan.from_dict(raw_plan)
            if requester_uid is not None and plan.config.owner_uid != requester_uid:
                raise HelperError("evidence owner must be the requesting user")
            raw_ca = request.get("ca_material")
            ca_material = None
            if raw_ca is not None:
                if not isinstance(raw_ca, dict) or not all(isinstance(v, str) and len(v) <= 128 * 1024 for v in raw_ca.values()):
                    raise HelperError("invalid custom CA material")
                ca_material = CAMaterial(raw_ca.get("certificate", "").encode(), raw_ca.get("private_key", "").encode(), raw_ca.get("chain", "").encode())
            return self.start(plan, ca_material=ca_material)
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
        if hasattr(socket, "SO_PEERCRED"):
            _pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        else:
            uid = os.getuid()  # Off-device socketpair tests; shipped helper runs on Linux.
        response = engine.dispatch(request, requester_uid=uid)
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
    listener.settimeout(0.25)
    while True:
        engine.watchdog()
        try:
            connection, _address = listener.accept()
        except socket.timeout:
            continue
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
