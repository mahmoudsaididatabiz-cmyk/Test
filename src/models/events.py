"""
Event models representing OS-level observations.

Maps kernel events → userspace data structures following the
AgentSight pipeline: eBPF → ring buffer → userspace → event model
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


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
    timestamp: datetime
    pid: int
    ppid: int
    uid: int
    gid: int
    comm: str
    executable: str
    cwd: str = "unknown"
    
    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2024-01-01T10:01:02Z",
                "pid": 1234,
                "ppid": 1200,
                "uid": 1000,
                "gid": 1000,
                "comm": "python",
                "executable": "/usr/bin/python3",
            }
        }


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
    
    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2024-01-01T10:01:05Z",
                "pid": 5678,
                "ppid": 1234,
                "uid": 1000,
                "comm": "curl",
                "executable": "/usr/bin/curl",
                "argv": ["curl", "https://api.example.com"],
                "event_type": "PROCESS_EXECUTION"
            }
        }


class FileAccessEvent(BaseOSEvent):
    """Represents a file access operation (open, read, etc.)."""
    event_type: EventType = EventType.FILE_ACCESS
    path: str
    flags: str = ""  # open flags (O_RDONLY, O_WRONLY, etc.)
    mode: int = 0o644
    
    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2024-01-01T10:01:07Z",
                "pid": 5679,
                "ppid": 1234,
                "uid": 1000,
                "comm": "curl",
                "executable": "/usr/bin/curl",
                "path": "/etc/passwd",
                "flags": "O_RDONLY",
                "event_type": "FILE_ACCESS"
            }
        }


class FileWriteEvent(BaseOSEvent):
    """Represents a file write operation."""
    event_type: EventType = EventType.FILE_WRITE
    path: str
    bytes_written: int = 0
    
    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2024-01-01T10:01:07Z",
                "pid": 5679,
                "ppid": 1234,
                "uid": 1000,
                "comm": "bash",
                "executable": "/bin/bash",
                "path": "/tmp/result.txt",
                "bytes_written": 1024,
                "event_type": "FILE_WRITE"
            }
        }


class FileDeleteEvent(BaseOSEvent):
    """Represents a file deletion event."""
    event_type: EventType = EventType.FILE_DELETE
    path: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2024-01-01T10:01:08Z",
                "pid": 5679,
                "ppid": 1234,
                "uid": 1000,
                "comm": "rm",
                "executable": "/bin/rm",
                "path": "/tmp/sensitive.txt",
                "event_type": "FILE_DELETE"
            }
        }


class NetworkConnectionEvent(BaseOSEvent):
    """Represents a network connection (connect syscall)."""
    event_type: EventType = EventType.NETWORK_CONNECTION
    remote_addr: str
    remote_port: int
    protocol: str = "tcp"  # tcp, udp, etc.
    
    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2024-01-01T10:01:06Z",
                "pid": 5678,
                "ppid": 1234,
                "uid": 1000,
                "comm": "curl",
                "executable": "/usr/bin/curl",
                "remote_addr": "api.example.com",
                "remote_port": 443,
                "protocol": "tcp",
                "event_type": "NETWORK_CONNECTION"
            }
        }


class LLMInteractionEvent(BaseModel):
    """
    Represents an LLM interaction/prompt.
    
    Part E: Correlation between LLM requests and OS activity.
    """
    timestamp: datetime
    session_id: str
    llm_provider: str = "unknown"
    prompt: str
    response: Optional[str] = None
    model: str = "unknown"
    
    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2024-01-01T10:01:02Z",
                "session_id": "session-42",
                "llm_provider": "openai",
                "prompt": "Download the report and save it locally",
                "model": "gpt-4"
            }
        }


class SecurityEvent(BaseModel):
    """
    Part D: Security event - represents a detected sensitive action.
    
    This is the high-level security finding that results from
    analyzing OS events against security rules.
    """
    timestamp: datetime
    type: str = "AI_AGENT_SECURITY_EVENT"
    severity: EventSeverity
    session_id: str
    pid: int
    ppid: int
    action: str  # FILE_ACCESS, PROCESS_EXECUTION, NETWORK_CONNECTION, etc.
    target: str  # path, command, remote address, etc.
    rule_name: str
    rule_description: str
    raw_events: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2024-01-01T10:01:07Z",
                "type": "AI_AGENT_SECURITY_EVENT",
                "severity": "HIGH",
                "session_id": "session-42",
                "pid": 5679,
                "ppid": 1234,
                "action": "FILE_ACCESS",
                "target": "/home/user/.ssh/id_rsa",
                "rule_name": "SENSITIVE_FILE_ACCESS",
                "rule_description": "Access to SSH private key detected",
            }
        }
