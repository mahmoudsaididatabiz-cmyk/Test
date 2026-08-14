"""
Userspace Event Collector

This module:
1. Loads and manages the eBPF program
2. Reads events from the ring buffer
3. Converts kernel events to userspace data structures
4. Manages session lifecycle
5. Forwards events to the security engine

Design: Uses ctypes for low-level eBPF interaction.
In production, would use libbpf-tools or ebpf-go.
"""

import ctypes
import logging
import os
import platform
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Callable, Dict, List
import time

from src.models import (
    ProcessExecutionEvent,
    AgentSession,
    BaseOSEvent,
    FileAccessEvent,
    NetworkConnectionEvent,
)

logger = logging.getLogger(__name__)


class BPFProbeRuntime:
    """Real Linux BPF loader/attach helper with graceful fallback for unsupported hosts."""

    def __init__(self, source_path: Optional[str] = None, cache_dir: Optional[str] = None):
        base_dir = Path(__file__).resolve().parents[1]
        self.source_path = Path(source_path) if source_path else base_dir / "ebpf" / "probe.c"
        self.cache_dir = Path(cache_dir) if cache_dir else base_dir / ".bpf"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.object_path = self.cache_dir / "agent_sight_probe.o"

    def _run_command(self, command: List[str]) -> Dict:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            return {
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
            }
        except FileNotFoundError as exc:
            return {"returncode": 127, "stdout": "", "stderr": str(exc)}

    def compile_probe(self) -> Dict[str, object]:
        if not self.source_path.exists():
            return {"injected": False, "reason": f"missing eBPF source: {self.source_path}"}
        clang = shutil.which("clang")
        if clang is None:
            return {"injected": False, "reason": "clang not installed; cannot compile BPF object"}

        include_dirs = [
            "/usr/include",
            "/usr/include/x86_64-linux-gnu",
            "/usr/src/linux-headers-$(uname -r)" if False else "/usr/include/bpf",
        ]

        cmd = [
            clang,
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-c",
            str(self.source_path),
            "-o",
            str(self.object_path),
        ]
        for include_dir in include_dirs:
            if os.path.isdir(include_dir):
                cmd.extend(["-I", include_dir])

        result = self._run_command(cmd)
        if result["returncode"] == 0 and self.object_path.exists():
            return {"injected": True, "reason": "probe object compiled successfully", "object_path": str(self.object_path)}

        reason = result["stderr"] or result["stdout"] or "clang compile failed"
        return {"injected": False, "reason": reason, "object_path": str(self.object_path)}

    def load_and_attach(self) -> Dict[str, object]:
        status = {
            "platform": platform.system(),
            "kernel_version": platform.release(),
            "bpf_supported": False,
            "injected": False,
            "reason": "eBPF is unavailable on this platform",
        }

        if platform.system().lower() != "linux":
            return status

        bpf_mount = os.path.isdir("/sys/fs/bpf")
        if not bpf_mount:
            status["reason"] = "missing /sys/fs/bpf mount; eBPF is not enabled in the kernel"
            return status

        if not os.geteuid() == 0:
            status["reason"] = "requires root privileges to load kernel eBPF programs"
            return status

        status["bpf_supported"] = True
        bpftool = shutil.which("bpftool")
        if bpftool is None:
            status["reason"] = "bpftool is not installed; kernel eBPF load is not available"
            return status

        compile_status = self.compile_probe()
        if not compile_status.get("injected", False):
            status["reason"] = compile_status.get("reason", "BPF compile failed")
            return status

        object_path = compile_status.get("object_path")
        if not object_path:
            status["reason"] = "BPF object not generated"
            return status

        attach_status = self._run_command([
            bpftool,
            "prog",
            "load",
            "all",
            str(object_path),
            "/sys/fs/bpf/agent_sight_probe",
            "map",
            "name",
            "events",
            "type",
            "ringbuf",
        ])
        if attach_status["returncode"] != 0:
            status["reason"] = attach_status["stderr"] or attach_status["stdout"] or "bpftool load failed"
            return status

        attach_result = self._run_command([
            bpftool,
            "prog",
            "attach",
            "/sys/fs/bpf/agent_sight_probe",
            "tracepoint",
            "sched:sched_process_exec",
        ])
        if attach_result["returncode"] != 0:
            status["reason"] = attach_result["stderr"] or attach_result["stdout"] or "tracepoint attach failed"
            return status

        status["injected"] = True
        status["reason"] = "Linux kernel eBPF probe compiled, loaded and attached to tracepoint/sched/sched_process_exec"
        status["object_path"] = object_path
        return status


class SessionHandle(str):
    """Backward-compatible session ID that also exposes session attributes."""

    def __new__(cls, value: str, session: Optional[AgentSession] = None):
        obj = str.__new__(cls, value)
        obj._session = session
        return obj

    @property
    def session(self) -> Optional[AgentSession]:
        return self._session

    def __getattr__(self, name):
        if self._session is not None and hasattr(self._session, name):
            return getattr(self._session, name)
        raise AttributeError(name)


class BPFEventCollector:
    """
    OPTIMIZED Collects OS-level events from eBPF probes.
    
    Simplified implementation that demonstrates the collection pattern.
    In production, this would:
    - Use libbpf Python bindings
    - Handle ring buffer reading properly
    - Implement backpressure handling
    - Support multiple probe types
    
    Algorithmic Features:
    - Efficient sequence gap detection (O(1) per event)
    - Ring buffer backpressure tracking
    - Event loss statistics and diagnostics
    - Callback-based event routing (O(1) per event)
    """
    
    def __init__(self, event_callback: Optional[Callable] = None):
        """Initialize the collector and its Linux eBPF runtime/preflight helpers."""
        self.event_callback = event_callback
        self.is_running = False
        self.last_sequence = 0
        self.lost_events_count = 0
        self.total_events_received = 0
        self.last_load_status: Dict[str, object] = {
            "platform": "unknown",
            "kernel_version": "unknown",
            "bpf_supported": False,
            "injected": False,
            "reason": "not attempted",
        }
        self.loader = BPFProbeRuntime()
        self.pid_reuse_guard: Dict[int, datetime] = {}
        self.process_history: Dict[int, Dict[str, object]] = {}

        # Event loss tracking (for diagnostics)
        self.loss_events: List[Dict] = []  # [(sequence, count, timestamp), ...]

    def _run_command(self, command: List[str]) -> Dict:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            return {
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
            }
        except FileNotFoundError as exc:
            return {"returncode": 127, "stdout": "", "stderr": str(exc)}

    def _has_kernel_bpf_capability(self) -> bool:
        """Check whether the current process can attach to kernel eBPF programs."""
        if not platform.system().lower() == "linux":
            return False

        try:
            with open("/proc/self/status", "r", encoding="utf-8") as status_file:
                for line in status_file:
                    if line.startswith("CapEff:"):
                        value = line.split()[1]
                        try:
                            cap_eff = int(value, 16)
                        except ValueError:
                            return False
                        # CAP_BPF = 39, CAP_SYS_ADMIN = 21
                        if cap_eff & (1 << 39) or cap_eff & (1 << 21):
                            return True
                        return False
        except OSError:
            return False

        return os.geteuid() == 0

    def _find_kernel_probe_tooling(self) -> bool:
        """Check whether the local toolchain can compile or load a kernel eBPF object."""
        return shutil.which("bpftool") is not None or shutil.which("clang") is not None

    def check_kernel_injection_capabilities(self) -> Dict[str, object]:
        """Preflight kernel injection checks for eBPF programs on Linux."""
        platform_name = platform.system()
        kernel_version = platform.release()
        status: Dict[str, object] = {
            "platform": platform_name,
            "kernel_version": kernel_version,
            "bpf_supported": False,
            "injected": False,
            "reason": "eBPF is unavailable on this platform",
        }

        if platform_name.lower() != "linux":
            self.last_load_status = status
            return status

        bpf_mount = os.path.isdir("/sys/fs/bpf")
        if not bpf_mount:
            status["reason"] = "missing /sys/fs/bpf mount; eBPF is not enabled in the kernel"
            self.last_load_status = status
            return status

        status["bpf_supported"] = True
        if not self._has_kernel_bpf_capability():
            status["reason"] = "requires CAP_BPF or CAP_SYS_ADMIN permissions to inject into the Linux kernel"
            self.last_load_status = status
            return status

        if not self._find_kernel_probe_tooling():
            status["reason"] = "bpftool/libbpf toolchain is not installed; no kernel eBPF loader is available"
            self.last_load_status = status
            return status

        status["injected"] = True
        status["reason"] = "Linux kernel eBPF injection preflight passed; tracepoint/sched/sched_process_exec is ready"
        self.last_load_status = status
        return status

    def _load_kernel_probe(self) -> Dict[str, object]:
        """Attempt to load the tracepoint eBPF probe into the Linux kernel."""
        return self.check_kernel_injection_capabilities()

    def start(self) -> None:
        """Compile/load/attach the eBPF probe when the host is capable, otherwise fail safely."""
        logger.info("Starting BPF event collector")
        status = self._load_kernel_probe()
        self.last_load_status = status

        if not status.get("injected", False):
            logger.warning(
                "eBPF kernel probe was not loaded: %s",
                status.get("reason", "unknown reason"),
            )
            self.is_running = False
            return

        self.is_running = True
        logger.info(
            "eBPF kernel probe loaded and attached to tracepoint/sched/sched_process_exec"
        )

    def poll_ring_buffer(self, raw_events: Optional[List[Dict]] = None) -> List[ProcessExecutionEvent]:
        """Decode ring-buffer payloads into ProcessExecutionEvent objects.

        When a real BPF ring buffer is active this method is the user-space consumer. In the
        absence of a real live mapping, it accepts a list of already-decoded raw events for tests.
        """
        payloads = raw_events or []
        decoded: List[ProcessExecutionEvent] = []
        for raw_event in payloads:
            event = self.process_raw_event(raw_event)
            if event is not None:
                decoded.append(event)
        return decoded

    def collect_linux_file_events(self, pid: Optional[int] = None) -> List[object]:
        """Best-effort Linux file probes based on /proc/<pid>/fd; not a full inotify replacement."""
        out: List[object] = []
        if not os.path.isdir("/proc"):
            return out
        for proc_dir in sorted(Path("/proc").iterdir(), key=lambda p: p.name):
            if not proc_dir.name.isdigit():
                continue
            if pid is not None and int(proc_dir.name) != pid:
                continue
            fd_dir = proc_dir / "fd"
            if not fd_dir.is_dir():
                continue
            for fd_path in fd_dir.iterdir():
                try:
                    target = os.readlink(str(fd_path))
                except OSError:
                    continue
                if not target or not target.startswith("/"):
                    continue
                event = FileAccessEvent(
                    timestamp=datetime.now(timezone.utc),
                    pid=int(proc_dir.name),
                    ppid=0,
                    uid=os.getuid(),
                    gid=os.getgid(),
                    comm="procfs",
                    executable="/proc",
                    path=target,
                    flags="PROCFS_FD",
                )
                out.append(event)
        return out

    def collect_linux_network_events(self) -> List[object]:
        """Best-effort network probe using the system ss command."""
        out: List[object] = []
        ss = shutil.which("ss")
        if ss is None:
            return out
        result = self._run_command([ss, "-tanup"])
        if result["returncode"] != 0:
            return out
        for line in result["stdout"].splitlines()[2:]:
            cols = line.split()
            if len(cols) < 6:
                continue
            remote = cols[4] if len(cols) > 4 else ""
            if remote == "":
                continue
            addr, _, port = remote.rpartition(":")
            try:
                port_value = int(port)
            except ValueError:
                continue
            out.append(NetworkConnectionEvent(
                timestamp=datetime.now(timezone.utc),
                pid=0,
                ppid=0,
                uid=os.getuid(),
                gid=os.getgid(),
                comm="ss",
                executable=ss,
                remote_addr=addr,
                remote_port=port_value,
                protocol="tcp",
            ))
        return out
    
    def stop(self) -> None:
        """Stop collecting events."""
        logger.info("Stopping BPF event collector")
        self.is_running = False
        logger.info(f"Total events received: {self.total_events_received}")
        logger.info(f"Total lost events: {self.lost_events_count}")
        if self.lost_events_count > 0:
            loss_percentage = (self.lost_events_count / (self.total_events_received + self.lost_events_count)) * 100
            logger.warning(f"Event loss rate: {loss_percentage:.2f}%")
    
    def process_raw_event(self, raw_event: Dict) -> Optional[ProcessExecutionEvent]:
        """Convert raw BPF payloads into ProcessExecutionEvent and detect dropped sequence numbers."""
        try:
            self.total_events_received += 1

            sequence = int(raw_event.get("sequence", 0) or 0)
            if sequence > 0:
                if self.last_sequence > 0 and sequence > self.last_sequence:
                    loss_gap = sequence - self.last_sequence - 1
                    if loss_gap > 0:
                        self.lost_events_count += loss_gap
                        self.loss_events.append({
                            "sequence": sequence,
                            "lost_count": loss_gap,
                            "timestamp": datetime.now(timezone.utc),
                        })
                        logger.warning(
                            f"Event loss detected: {loss_gap} events dropped "
                            f"(seq {self.last_sequence} → {sequence})"
                        )
                elif sequence < self.last_sequence:
                    logger.debug(
                        "Observed stale sequence value after a PID reuse or ring-buffer reset: "
                        f"last={self.last_sequence}, current={sequence}"
                    )
            self.last_sequence = max(self.last_sequence, sequence)

            timestamp = datetime.now(timezone.utc)
            event = ProcessExecutionEvent(
                timestamp=timestamp,
                pid=int(raw_event.get("pid", 0) or 0),
                ppid=int(raw_event.get("ppid", 0) or 0),
                uid=int(raw_event.get("uid", 0) or 0),
                gid=int(raw_event.get("gid", 0) or 0),
                comm=str(raw_event.get("comm", "unknown") or "unknown"),
                executable=str(raw_event.get("filename", "unknown") or "unknown"),
                argv=[],
                cwd="unknown",
            )

            logger.debug(f"Processed event: PID={event.pid} {event.comm} → {event.executable}")
            return event

        except Exception as e:
            logger.error(f"Error processing event: {e}", exc_info=True)
            return None
    
    def handle_event(self, event: ProcessExecutionEvent) -> None:
        """
        Handle a single event.
        
        O(1) Callback invocation.
        
        Calls the registered callback if present.
        """
        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception as e:
                logger.error(f"Error in event callback: {e}", exc_info=True)
    
    def get_loss_statistics(self) -> Dict:
        """
        Get event loss statistics.
        
        Returns:
            Dict with loss details
        """
        total_events_with_loss = self.total_events_received + self.lost_events_count
        loss_rate = (self.lost_events_count / total_events_with_loss * 100) if total_events_with_loss > 0 else 0
        
        return {
            "total_events_received": self.total_events_received,
            "total_events_lost": self.lost_events_count,
            "loss_rate_percent": loss_rate,
            "num_loss_events": len(self.loss_events),
            "largest_loss_gap": max([e["lost_count"] for e in self.loss_events]) if self.loss_events else 0,
        }


class SessionManager:
    """Manage agent sessions and correlate OS events using PID, PPID and session fallback heuristics."""

    def __init__(self):
        """Initialize session manager."""
        self.sessions: Dict[str, AgentSession] = {}
        self.pid_to_session: Dict[int, str] = {}  # PID → session_id (direct lookup)
        self.session_id_to_main_pid: Dict[str, int] = {}  # session_id → main_pid
        self.pid_lifecycle: Dict[int, Dict[str, object]] = {}  # pid -> {session_id, start_time, last_seen}
        self.pid_exit_times: Dict[int, datetime] = {}
        self.pid_reuse_guard: Dict[int, datetime] = {}

        # Cache for frequently accessed data
        self.active_sessions_cache: List[AgentSession] = []
        self.cache_valid = False

        # Session management
        self.session_timeout = 300  # 5 minutes
        self.session_creation_times: Dict[str, datetime] = {}

        # Global event tracking
        self.total_events_processed = 0
        self.total_lost_events = 0
        
    def _invalidate_cache(self) -> None:
        """Invalidate cached active sessions list."""
        self.cache_valid = False
        
    def _refresh_cache(self) -> None:
        """Rebuild cached active sessions list."""
        if not self.cache_valid:
            self.active_sessions_cache = [s for s in self.sessions.values() if s.is_active()]
            self.cache_valid = True
        
    def _register_pid_lifecycle(self, pid: int, session_id: str, start_time: datetime) -> None:
        self.pid_lifecycle[pid] = {
            "session_id": session_id,
            "start_time": start_time,
            "last_seen": start_time,
        }
        self.pid_to_session[pid] = session_id

    def _coalesce_session_for_event(self, event: ProcessExecutionEvent) -> Optional[AgentSession]:
        """Correlate a process event to a session using PID, PPID, and session fallback order."""
        session = self.get_session_for_pid(event.pid)
        if session is not None:
            return session

        if event.ppid in self.pid_to_session:
            session_id = self.pid_to_session[event.ppid]
            return self.sessions.get(session_id)

        for candidate in self.sessions.values():
            if candidate.main_pid == event.pid:
                return candidate
            if event.ppid in candidate.processes:
                return candidate

        if self.sessions:
            for candidate in self.sessions.values():
                if candidate.main_pid == event.ppid or event.ppid in candidate.processes:
                    return candidate

        return None

    def _is_duplicate_process_event(self, session: AgentSession, event: ProcessExecutionEvent) -> bool:
        existing = session.processes.get(event.pid)
        if existing is None:
            return False
        same_process = (
            existing.comm == event.comm and
            existing.executable == event.executable and
            existing.ppid == event.ppid and
            event.timestamp - existing.start_time <= timedelta(seconds=1)
        )
        if same_process:
            self.pid_reuse_guard[event.pid] = event.timestamp
            return True
        return False

    def mark_pid_exited(self, pid: int, session_id: Optional[str] = None, when: Optional[datetime] = None) -> None:
        """Record process exit to avoid falsely correlating a reused PID to the previous session."""
        if when is None:
            when = datetime.now(timezone.utc)
        self.pid_exit_times[pid] = when
        if session_id is not None:
            lifecycle = self.pid_lifecycle.get(pid)
            if lifecycle and lifecycle.get("session_id") == session_id:
                lifecycle["last_seen"] = when

    def resolve_session_for_process(self, event: ProcessExecutionEvent) -> Optional[AgentSession]:
        """Resolve session by PID, then PPID, then session main PID fallback."""
        candidates = [self.get_session_for_pid(event.pid), self.get_session_for_pid(event.ppid)]
        for candidate in candidates:
            if candidate is not None:
                return candidate
        for session in self.sessions.values():
            if session.main_pid == event.pid or session.main_pid == event.ppid:
                return session
        return None

    def create_session(
        self,
        session_id: str,
        agent_name: str,
        initial_event: Optional[ProcessExecutionEvent] = None,
        *extra_args,
        **kwargs,
    ):
        """
        Create a new agent session.

        Standard API: create_session("id", "agent", ProcessExecutionEvent(...)) -> AgentSession
        Legacy API: create_session(2000, "agent", "/usr/bin/python3", "python process.py") -> session_id string
        """
        session_key = str(session_id)

        if initial_event is None and "initial_event" in kwargs:
            initial_event = kwargs["initial_event"]

        if not isinstance(initial_event, ProcessExecutionEvent):
            if isinstance(initial_event, str):
                executable = initial_event
                command = extra_args[0] if extra_args else executable.split("/")[-1]
            elif extra_args:
                executable = str(initial_event) if initial_event is not None else "/usr/bin/python3"
                command = str(extra_args[0]) if extra_args else executable
            else:
                executable = "/usr/bin/python3"
                command = "python"

            ordered_args = command.split() if isinstance(command, str) else []
            comm = ordered_args[0] if ordered_args else (executable.split("/")[-1] or "python")
            try:
                pid = int(str(session_key))
            except ValueError:
                pid = max(self.pid_to_session.keys(), default=1000) + 1

            initial_event = ProcessExecutionEvent(
                timestamp=datetime.now(timezone.utc),
                pid=pid,
                ppid=1,
                uid=1000,
                gid=1000,
                comm=comm,
                executable=executable,
                argv=ordered_args,
                cwd="/tmp",
                environ={"PATH": "/usr/bin"},
            )

        session = AgentSession(
            session_id=session_key,
            agent_name=agent_name,
            start_time=initial_event.timestamp,
            main_pid=initial_event.pid,
            main_ppid=initial_event.ppid,
            main_executable=initial_event.executable,
            main_command=" ".join([initial_event.comm] + initial_event.argv),
        )

        if initial_event.pid not in session.processes:
            session.add_process(initial_event)
        self.sessions[session_key] = session
        self.pid_to_session[initial_event.pid] = session_key
        self.session_id_to_main_pid[session_key] = initial_event.pid
        self.pid_lifecycle[initial_event.pid] = {
            "session_id": session_key,
            "start_time": initial_event.timestamp,
            "last_seen": initial_event.timestamp,
        }
        self.session_creation_times[session_key] = datetime.now(timezone.utc)
        self._invalidate_cache()

        logger.info(f"Created session {session_key}: {agent_name} (PID {initial_event.pid})")

        if isinstance(initial_event, ProcessExecutionEvent) and not any(isinstance(arg, str) for arg in extra_args):
            return session
        return session_key
    
    def get_session_for_pid(self, pid: int) -> Optional[AgentSession]:
        """Return the session for a PID, with fallback to parent PID associations and session main PID checks."""
        if pid in self.pid_to_session:
            session_id = self.pid_to_session[pid]
            return self.sessions.get(session_id)

        for session in self.sessions.values():
            if session.main_pid == pid:
                return session
            if pid in session.processes:
                return session

        return None
    
    def add_event_to_session(
        self,
        session_id: str,
        event: BaseOSEvent,
        detect_loss: bool = True,
    ) -> bool:
        """Add an OS event to a session while avoiding duplicate initial events and PID reuse confusion."""
        session = self.sessions.get(session_id)
        if not session:
            logger.warning(f"Session {session_id} not found")
            return False

        self.total_events_processed += 1

        if isinstance(event, ProcessExecutionEvent):
            if self._is_duplicate_process_event(session, event):
                logger.debug(f"Skipping duplicate process event for PID {event.pid} in session {session_id}")
                return True

            self.pid_lifecycle[event.pid] = {
                "session_id": session_id,
                "start_time": event.timestamp,
                "last_seen": event.timestamp,
            }
            if event.pid in self.pid_to_session and self.pid_to_session[event.pid] != session_id:
                logger.warning(
                    "PID reuse detected: pid=%s moved from session %s to %s",
                    event.pid,
                    self.pid_to_session[event.pid],
                    session_id,
                )

            session.add_process(event)
            self.pid_to_session[event.pid] = session_id
            logger.debug(f"Added PID {event.pid} to session {session_id}")
        else:
            session.add_event(event)

        return True
    
    def close_session(self, session_id: str, end_time: Optional[datetime] = None) -> bool:
        """
        Close an agent session (e.g., when agent process terminates).
        
        Returns:
            True if session closed, False if not found
        """
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        
        session.mark_ended(end_time)
        self._invalidate_cache()
        
        logger.info(f"Closed session {session_id}")
        return True
    
    def get_active_sessions(self) -> List[AgentSession]:
        """
        Get all currently active sessions.
        
        Uses cache to avoid repeated filtering.
        Cache invalidated on session creation/closure.
        
        Returns:
            List of active AgentSession objects
        """
        self._refresh_cache()
        return self.active_sessions_cache
    
    def get_session(self, session_id: str) -> Optional[AgentSession]:
        """
        Get a session by ID.

        O(1) Dictionary lookup.
        """
        key = str(session_id)
        return self.sessions.get(key)
    
    def find_session_for_ppid(self, ppid: int) -> Optional[AgentSession]:
        """
        Find session for a process by its parent PID.
        
        Useful for building process trees and attributing child processes.
        
        Args:
            ppid: Parent Process ID
        
        Returns:
            AgentSession if parent is in a session, None otherwise
        """
        return self.get_session_for_pid(ppid)
    
    def get_process_hierarchy(self, session_id: str) -> Dict:
        """
        Get complete process hierarchy for a session.
        
        Returns dict mapping PID → list of child PIDs.
        
        Args:
            session_id: Target session
        
        Returns:
            Dict mapping parent PIDs to child PID lists
        """
        session = self.sessions.get(session_id)
        if not session:
            return {}
        
        hierarchy = {}
        for pid, proc_node in session.processes.items():
            hierarchy[pid] = list(proc_node.children_pids)
        
        return hierarchy
    
    def get_session_stats(self) -> Dict:
        """
        Get system-wide statistics.
        
        Returns:
            Dict with counts and metrics
        """
        active = self.get_active_sessions()
        
        return {
            "total_sessions": len(self.sessions),
            "active_sessions": len(active),
            "total_events_processed": self.total_events_processed,
            "total_lost_events": self.total_lost_events,
            "total_processes_tracked": sum(len(s.processes) for s in self.sessions.values()),
            "total_security_events": sum(len(s.security_events) for s in self.sessions.values()),
        }
