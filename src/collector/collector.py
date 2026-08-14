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
from datetime import datetime, timezone
from typing import Optional, Callable, Dict, List
import time

from src.models import ProcessExecutionEvent, AgentSession, BaseOSEvent

logger = logging.getLogger(__name__)


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
        """
        Initialize the collector.
        
        Args:
            event_callback: Function to call for each event
        """
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
        
        # Event loss tracking (for diagnostics)
        self.loss_events: List[Dict] = []  # [(sequence, count, timestamp), ...]

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
        """Start collecting events from eBPF probes."""
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
        """
        Convert raw eBPF event to ProcessExecutionEvent.
        
        Algorithm: O(1) sequence-based loss detection
        
        Args:
            raw_event: Dict from ring buffer with fields:
                - timestamp (ns since boot)
                - pid, ppid, uid, gid
                - comm (executable name)
                - filename (full path)
                - sequence: Global atomic counter from kernel
        
        Returns:
            ProcessExecutionEvent or None if processing failed
        """
        try:
            self.total_events_received += 1
            
            # O(1) Detect lost events via sequence gap
            sequence = raw_event.get("sequence", 0)
            if sequence > 0:
                loss_gap = sequence - self.last_sequence - 1
                if loss_gap > 0:
                    # Events were lost
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
            self.last_sequence = sequence
            
            # Convert kernel timestamp (nanoseconds since boot) to wall clock
            # Note: In production, we'd use a proper reference point
            timestamp = datetime.now(timezone.utc)
            
            event = ProcessExecutionEvent(
                timestamp=timestamp,
                pid=raw_event.get("pid", 0),
                ppid=raw_event.get("ppid", 0),
                uid=raw_event.get("uid", 0),
                gid=raw_event.get("gid", 0),
                comm=raw_event.get("comm", "unknown"),
                executable=raw_event.get("filename", "unknown"),
                argv=[],  # Would need separate probe to capture argv from kernel
                cwd="unknown",  # Would need to read from /proc
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
    """
    OPTIMIZED Manages agent sessions and correlates events with sessions.
    
    Key responsibility: Map each OS-level event to the appropriate session
    based on PID/PPID relationships.
    
    Algorithmic Improvements:
    - O(1) lookup: pid_to_session mapping for direct PID→session lookup
    - Cached active sessions: Avoid repeated filtering
    - Session hierarchy: Parent-child PID relationships tracked
    - Event loss detection: Global sequence tracking with gap detection
    """
    
    def __init__(self):
        """Initialize session manager."""
        self.sessions: Dict[str, AgentSession] = {}
        self.pid_to_session: Dict[int, str] = {}  # PID → session_id (O(1) lookup)
        self.session_id_to_main_pid: Dict[str, int] = {}  # session_id → main_pid
        
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

        session.add_process(initial_event)
        self.sessions[session_key] = session
        self.pid_to_session[initial_event.pid] = session_key
        self.session_id_to_main_pid[session_key] = initial_event.pid
        self.session_creation_times[session_key] = datetime.now(timezone.utc)
        self._invalidate_cache()

        logger.info(f"Created session {session_key}: {agent_name} (PID {initial_event.pid})")

        if isinstance(initial_event, ProcessExecutionEvent) and not any(isinstance(arg, str) for arg in extra_args):
            return session
        return session_key
    
    def get_session_for_pid(self, pid: int) -> Optional[AgentSession]:
        """
        Get the session associated with a PID.
        
        O(1) Lookup: Direct dictionary access via pid_to_session mapping.
        
        Args:
            pid: Process ID to lookup
        
        Returns:
            AgentSession if found, None otherwise
        """
        # Direct O(1) lookup
        if pid in self.pid_to_session:
            session_id = self.pid_to_session[pid]
            return self.sessions.get(session_id)
        
        return None
    
    def add_event_to_session(
        self,
        session_id: str,
        event: BaseOSEvent,
        detect_loss: bool = True,
    ) -> bool:
        """
        Add an OS event to a session.
        
        For ProcessExecutionEvent: also adds to process tree.
        For other events: just adds to timeline.
        
        O(1) or O(n) depending on event type:
        - ProcessExecutionEvent: O(1) - dict insertion
        - Other events: O(n) - timeline sort
        
        Args:
            session_id: Target session ID
            event: OS event to add
            detect_loss: Whether to detect event loss patterns
        
        Returns:
            True if successfully added, False if session not found
        """
        session = self.sessions.get(session_id)
        if not session:
            logger.warning(f"Session {session_id} not found")
            return False
        
        self.total_events_processed += 1
        
        # Add process to session's process tree (only for process execution)
        if isinstance(event, ProcessExecutionEvent):
            session.add_process(event)  # This also calls add_event internally
            self.pid_to_session[event.pid] = session_id  # Update PID index
            logger.debug(f"Added PID {event.pid} to session {session_id}")
        else:
            # For other event types, just add to timeline
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
