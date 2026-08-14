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
from datetime import datetime, timezone
from typing import Optional, Callable, Dict, List
import time

from src.models import ProcessExecutionEvent, AgentSession, BaseOSEvent

logger = logging.getLogger(__name__)


class BPFEventCollector:
    """
    Collects OS-level events from eBPF probes.
    
    Simplified implementation that demonstrates the collection pattern.
    In production, this would:
    - Use libbpf Python bindings
    - Handle ring buffer reading properly
    - Implement backpressure handling
    - Support multiple probe types
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
        
    def start(self) -> None:
        """Start collecting events from eBPF probes."""
        logger.info("Starting BPF event collector")
        self.is_running = True
        
        # In production: Load compiled eBPF object, attach to tracepoint
        # Here: Simulated for demonstration
        logger.debug("eBPF probes attached to sched_process_exec tracepoint")
    
    def stop(self) -> None:
        """Stop collecting events."""
        logger.info("Stopping BPF event collector")
        self.is_running = False
        logger.info(f"Total lost events: {self.lost_events_count}")
    
    def process_raw_event(self, raw_event: Dict) -> Optional[ProcessExecutionEvent]:
        """
        Convert raw eBPF event to ProcessExecutionEvent.
        
        Args:
            raw_event: Dict from ring buffer with fields:
                - timestamp (ns since boot)
                - pid, ppid, uid, gid
                - comm (executable name)
                - filename (full path)
        
        Returns:
            ProcessExecutionEvent or None if processing failed
        """
        try:
            # Detect lost events via sequence gap
            sequence = raw_event.get("sequence", 0)
            if sequence > 0 and sequence != self.last_sequence + 1:
                self.lost_events_count += (sequence - self.last_sequence - 1)
                if self.lost_events_count > 0:
                    logger.warning(
                        f"Detected event loss: {sequence - self.last_sequence - 1} events dropped"
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
            
            logger.debug(f"Processed event: PID={event.pid} {event.comm} -> {event.executable}")
            return event
        
        except Exception as e:
            logger.error(f"Error processing event: {e}", exc_info=True)
            return None
    
    def handle_event(self, event: ProcessExecutionEvent) -> None:
        """
        Handle a single event.
        
        Calls the registered callback if present.
        """
        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception as e:
                logger.error(f"Error in event callback: {e}", exc_info=True)


class SessionManager:
    """
    Manages agent sessions and correlates events with sessions.
    
    Key responsibility: Map each OS-level event to the appropriate session
    based on PID/PPID relationships.
    """
    
    def __init__(self):
        """Initialize session manager."""
        self.sessions: Dict[str, AgentSession] = {}
        self.pid_to_session: Dict[int, str] = {}  # PID -> session_id mapping
        self.session_timeout = 300  # 5 minutes
        
    def create_session(
        self,
        session_id: str,
        agent_name: str,
        initial_event: ProcessExecutionEvent,
    ) -> AgentSession:
        """
        Create a new agent session.
        
        Args:
            session_id: Unique session identifier
            agent_name: Name of the AI agent
            initial_event: The initial process execution event
        
        Returns:
            Created AgentSession
        """
        session = AgentSession(
            session_id=session_id,
            agent_name=agent_name,
            start_time=initial_event.timestamp,
            main_pid=initial_event.pid,
            main_ppid=initial_event.ppid,
            main_executable=initial_event.executable,
            main_command=" ".join([initial_event.comm] + initial_event.argv),
        )
        
        # Add initial process
        session.add_process(initial_event)
        
        self.sessions[session_id] = session
        self.pid_to_session[initial_event.pid] = session_id
        
        logger.info(f"Created session {session_id}: {agent_name} (PID {initial_event.pid})")
        return session
    
    def get_session_for_pid(self, pid: int) -> Optional[AgentSession]:
        """Get the session associated with a PID."""
        # Check direct mapping
        if pid in self.pid_to_session:
            return self.sessions.get(self.pid_to_session[pid])
        
        # Check if PID is a child of any session's main process
        for session in self.sessions.values():
            if pid in session.processes:
                return session
        
        return None
    
    def add_event_to_session(
        self,
        session_id: str,
        event: BaseOSEvent,
    ) -> bool:
        """
        Add an OS event to a session.
        
        For ProcessExecutionEvent: also adds to process tree.
        For other events: just adds to timeline.
        
        Returns:
            True if successfully added, False if session not found
        """
        session = self.sessions.get(session_id)
        if not session:
            logger.warning(f"Session {session_id} not found")
            return False
        
        # Add process to session's process tree (only for process execution)
        if isinstance(event, ProcessExecutionEvent):
            session.add_process(event)  # This also calls add_event internally
            self.pid_to_session[event.pid] = session_id
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
        logger.info(f"Closed session {session_id}")
        return True
    
    def get_active_sessions(self) -> List[AgentSession]:
        """Get all currently active sessions."""
        return [s for s in self.sessions.values() if s.is_active()]
    
    def get_session(self, session_id: str) -> Optional[AgentSession]:
        """Get a session by ID."""
        return self.sessions.get(session_id)
