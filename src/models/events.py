"""
Event models representing OS-level observations.

Maps kernel events → userspace data structures following the
AgentSight pipeline: eBPF → ring buffer → userspace → event model
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict


class EventSeverity(str, Enum):
    """Security event severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    """Types of OS-level events."""
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    FILE_ACCESS = "FILE_ACCESS"
    FILE_WRITE = "FILE_WRITE"
    FILE_DELETE = "FILE_DELETE"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"
    LLM_INTERACTION = "LLM_INTERACTION"


class BaseOSEvent(BaseModel):
    """Base class for all OS-level events."""
    model_config = ConfigDict(extra="allow")

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    pid: int = 0
    ppid: int = 0
    uid: int = 0
    gid: int = 0
    comm: str = ""
    executable: str = ""
    cwd: str = "unknown"


class ProcessExecutionEvent(BaseOSEvent):
    """
    Represents a process execution event (execve syscall).

    Part B: eBPF captures this from kernel syscall tracing.
    This is the fundamental building block for session tracking.
    """
    event_type: EventType = EventType.PROCESS_EXECUTION
    argv: List[str] = Field(default_factory=list)
    environ: Dict[str, str] = Field(default_factory=dict)
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None


class FileAccessEvent(BaseOSEvent):
    """Represents a file access operation (open, read, etc.)."""
    event_type: EventType = EventType.FILE_ACCESS
    path: str = ""
    flags: str = ""  # open flags (O_RDONLY, O_WRONLY, etc.)
    mode: int = 0o644


class FileWriteEvent(BaseOSEvent):
    """Represents a file write operation."""
    event_type: EventType = EventType.FILE_WRITE
    path: str = ""
    bytes_written: int = 0


class FileDeleteEvent(BaseOSEvent):
    """Represents a file deletion event."""
    event_type: EventType = EventType.FILE_DELETE
    path: str = ""


class NetworkConnectionEvent(BaseOSEvent):
    """Represents a network connection (connect syscall)."""
    event_type: EventType = EventType.NETWORK_CONNECTION
    remote_addr: str = ""
    remote_port: int = 0
    protocol: str = "tcp"  # tcp, udp, etc.


class LLMInteractionEvent(BaseModel):
    """
    Represents an LLM interaction/prompt.

    Part E: Correlation between LLM requests and OS activity.
    """
    model_config = ConfigDict(extra="allow")

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: str = ""
    llm_provider: str = "unknown"
    prompt: str = ""
    response: Optional[str] = None
    model: str = "unknown"
    pid: int = 0
    ppid: int = 0
    uid: int = 0
    gid: int = 0
    comm: str = ""
    executable: str = ""
    cwd: str = "unknown"
    duration_ms: Optional[int] = None
    event_type: EventType = EventType.LLM_INTERACTION


class SecurityEvent(BaseModel):
    """
    Part D: Security event - represents a detected sensitive action.

    This is the high-level security finding that results from
    analyzing OS events against security rules.
    """
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    type: str = "AI_AGENT_SECURITY_EVENT"
    severity: EventSeverity = EventSeverity.MEDIUM
    session_id: str = ""
    pid: int = 0
    ppid: int = 0
    action: str = "UNKNOWN"  # FILE_ACCESS, PROCESS_EXECUTION, NETWORK_CONNECTION, etc.
    target: str = "unknown"  # path, command, remote address, etc.
    rule_name: str = "UNKNOWN_RULE"
    rule_description: str = ""
    raw_events: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
