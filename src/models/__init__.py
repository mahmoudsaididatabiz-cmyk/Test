"""
Data models for AgentSight security monitoring system.

Part C: Agent Session Model
This module defines the core data structures that represent:
- Security events at OS level
- Process execution chains
- Agent sessions and their lifecycle
- File and network operations
"""

from .events import (
    EventSeverity,
    EventType,
    BaseOSEvent,
    SecurityEvent,
    ProcessExecutionEvent,
    FileAccessEvent,
    FileWriteEvent,
    FileDeleteEvent,
    NetworkConnectionEvent,
    LLMInteractionEvent,
)
from .session import (
    ProcessNode,
    AgentSession,
    SessionTimeline,
    SessionSummary,
)

__all__ = [
    "EventSeverity",
    "EventType",
    "BaseOSEvent",
    "SecurityEvent",
    "ProcessExecutionEvent",
    "FileAccessEvent",
    "FileWriteEvent",
    "FileDeleteEvent",
    "NetworkConnectionEvent",
    "LLMInteractionEvent",
    "ProcessNode",
    "AgentSession",
    "SessionTimeline",
    "SessionSummary",
]
