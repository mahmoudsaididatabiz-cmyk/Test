"""
Agent Session model - represents a complete AI agent execution session.

Part C: Implements the Agent Session structure with:
- Process tree tracking (parent-child relationships)
- Event timeline
- Session lifecycle management
- Correlation of child processes to main agent process
"""

from datetime import datetime
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from .events import (
    ProcessExecutionEvent,
    FileAccessEvent,
    FileWriteEvent,
    FileDeleteEvent,
    NetworkConnectionEvent,
    LLMInteractionEvent,
    SecurityEvent,
    BaseOSEvent,
)


class ProcessNode(BaseModel):
    """
    Represents a process in the session's process tree.
    
    Design decision: Track processes by PID with parent-child relationships
    to build the process tree and understand the execution hierarchy.
    """
    model_config = ConfigDict(extra="allow")

    pid: int
    ppid: int
    comm: str
    executable: str
    argv: List[str] = Field(default_factory=list)
    start_time: datetime
    end_time: Optional[datetime] = None
    exit_code: Optional[int] = None
    children_pids: Set[int] = Field(default_factory=set)
    
    model_config = ConfigDict(extra="allow")


class SessionTimeline(BaseModel):
    """
    Timeline of events within a session.

    Chronologically ordered events that occurred during the agent session,
    from LLM interaction to OS-level observations.
    """
    events: List[Dict] = Field(default_factory=list)  # Polymorphic events
    security_events: List[SecurityEvent] = Field(default_factory=list)

    def add_event(self, event: BaseOSEvent) -> None:
        """Add an OS event to timeline (maintains chronological order)."""
        payload = event.model_dump(mode="json")
        if isinstance(payload.get("timestamp"), str):
            payload["timestamp"] = payload["timestamp"]
        self.events.append(payload)
        self.events.sort(key=lambda e: datetime.fromisoformat(str(e["timestamp"])))

    def add_security_event(self, event: SecurityEvent) -> None:
        """Add a security event."""
        self.security_events.append(event)
        self.security_events.sort(key=lambda e: e.timestamp)


class SessionSummary(BaseModel):
    """Summary statistics for a session."""
    total_processes: int = 0
    total_events: int = 0
    total_security_events: int = 0
    unique_files_accessed: int = 0
    unique_commands: int = 0
    network_connections_count: int = 0
    duration: float = 0.0

    @property
    def duration_seconds(self) -> float:
        return self.duration


class AgentSession(BaseModel):
    """
    Part C: Complete AI Agent Session Model
    
    Represents a single execution of an AI agent, from start to completion.
    Tracks all OS-level activity associated with the agent.
    
    Design principles:
    1. Parent PID identification: Track the main agent process
    2. Process tree: Build hierarchy of parent-child relationships
    3. Event association: Assign all events to appropriate processes
    4. Session timeline: Chronological record of all activity
    5. Security analysis: Detect and record suspicious activity
    """
    model_config = ConfigDict(extra="allow")

    # Session identification
    session_id: str
    agent_name: str = "unknown"
    start_time: datetime
    end_time: Optional[datetime] = None
    
    # Main agent process info
    main_pid: int
    main_ppid: int
    main_executable: str
    main_command: str
    
    # Process tracking
    # Key design choice: Use dict for O(1) process lookup by PID
    processes: Dict[int, ProcessNode] = Field(default_factory=dict)
    
    # Event tracking
    timeline: SessionTimeline = Field(default_factory=SessionTimeline)
    
    # File access tracking (for summary)
    files_accessed: Dict[str, List[str]] = Field(default_factory=dict)  # path -> [operations]
    
    # Network activity
    network_connections: List[NetworkConnectionEvent] = Field(default_factory=list)
    
    # LLM interactions that triggered this session
    llm_interactions: List[LLMInteractionEvent] = Field(default_factory=list)
    
    # Security findings
    security_events: List[SecurityEvent] = Field(default_factory=list)
    
    # Metadata
    environment: Dict[str, str] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    
    # =========================================================================
    # Core Methods for Session Management
    # =========================================================================
    
    def add_process(self, event: ProcessExecutionEvent) -> ProcessNode:
        """
        Add a new process to the session.
        
        Key design decision: Use PPid to establish parent-child relationships.
        When we see a process with PPID, we can link it to its parent.
        """
        node = ProcessNode(
            pid=event.pid,
            ppid=event.ppid,
            comm=event.comm,
            executable=event.executable,
            argv=event.argv,
            start_time=event.timestamp,
        )
        self.processes[event.pid] = node
        
        # Link to parent (if parent exists in this session)
        if event.ppid in self.processes:
            self.processes[event.ppid].children_pids.add(event.pid)
        
        # Also add to timeline as an event
        self.add_event(event)
        
        return node
    
    def add_event(self, event: BaseOSEvent) -> None:
        """Add an OS event to the session's timeline."""
        self.timeline.add_event(event)

        # Track file accesses
        if isinstance(event, (FileAccessEvent, FileWriteEvent, FileDeleteEvent)):
            path = event.path
            op = event.event_type.value
            if path not in self.files_accessed:
                self.files_accessed[path] = []
            self.files_accessed[path].append(op)

        # Track network connections
        if isinstance(event, NetworkConnectionEvent):
            self.network_connections.append(event)
    
    def add_security_event(self, event: SecurityEvent) -> None:
        """Add a security event (suspicious activity detected)."""
        self.security_events.append(event)
        self.timeline.add_security_event(event)
    
    def add_llm_interaction(self, event: LLMInteractionEvent) -> None:
        """Add an LLM interaction that may have triggered this session."""
        self.llm_interactions.append(event)
    
    def get_process_tree(self) -> Dict:
        """
        Build a hierarchical representation of the process tree.
        
        Returns a dict suitable for visualization:
        {
            "pid": 1234,
            "comm": "python",
            "children": [
                {"pid": 5678, "comm": "curl", "children": []}
            ]
        }
        """
        def build_tree(pid: int) -> Dict:
            if pid not in self.processes:
                return {"pid": pid, "comm": "unknown", "children": []}
            
            proc = self.processes[pid]
            return {
                "pid": proc.pid,
                "comm": proc.comm,
                "executable": proc.executable,
                "children": [build_tree(child) for child in sorted(proc.children_pids)]
            }
        
        return build_tree(self.main_pid)
    
    def get_summary(self) -> SessionSummary:
        """Generate a summary of the session."""
        duration = 0.0
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()

        return SessionSummary(
            total_processes=len(self.processes),
            total_events=len(self.timeline.events),
            total_security_events=len(self.security_events),
            unique_files_accessed=len(self.files_accessed),
            unique_commands=len(set(p.comm for p in self.processes.values())),
            network_connections_count=len(self.network_connections),
            duration=duration,
        )
    
    def mark_ended(self, end_time: datetime) -> None:
        """Mark the session as ended."""
        self.end_time = end_time
        
        # Update process end times for processes we know about
        for pid, proc in self.processes.items():
            if proc.end_time is None:
                proc.end_time = end_time
    
    def is_active(self) -> bool:
        """Check if session is still active."""
        return self.end_time is None
