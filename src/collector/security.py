"""
Security Rules Engine

Part D: Detect suspicious/sensitive actions performed by AI agents.

This module implements security rules that identify potentially dangerous
operations such as:
- Execution of sensitive commands (curl, wget, ssh, sudo, chmod, rm)
- Access to sensitive files (/etc/passwd, /etc/shadow, ~/.ssh, .env)
- Network connections to external hosts
- File deletion or modification

Design: Rules are data-driven (JSON-based) for easy extension.
"""

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from src.models import (
    ProcessExecutionEvent,
    FileAccessEvent,
    FileWriteEvent,
    FileDeleteEvent,
    NetworkConnectionEvent,
    SecurityEvent,
    EventSeverity,
    BaseOSEvent,
)

logger = logging.getLogger(__name__)


@dataclass
class SecurityRule:
    """Represents a security detection rule."""
    name: str
    description: str
    event_type: str  # PROCESS_EXECUTION, FILE_ACCESS, NETWORK_CONNECTION, etc.
    severity: EventSeverity
    check_fn: callable  # Function that checks if event violates rule


class SecurityEngine:
    """
    Part D: Security detection engine.
    
    Analyzes OS events and detects potentially sensitive actions.
    Emits SecurityEvent when a rule is violated.
    """
    
    # Sensitive commands that should raise alerts
    SENSITIVE_COMMANDS = {
        "curl",
        "wget",
        "ssh",
        "scp",
        "sftp",
        "sudo",
        "chmod",
        "chown",
        "rm",
        "dd",
        "nc",
        "ncat",
        "telnet",
        "git",  # Can exfiltrate data via git push
        "gpg",
        "openssl",
    }
    
    # Sensitive file paths
    SENSITIVE_PATHS = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh",
        "/home/*/.ssh",
        "~/.ssh",
        "~/.env",
        "~/.bash_history",
        "/proc/sched_debug",
        "/proc/keys",
        "/var/log/auth.log",
    }
    
    def __init__(self):
        """Initialize the security engine with default rules."""
        self.rules: List[SecurityRule] = []
        self._register_default_rules()
    
    def _register_default_rules(self) -> None:
        """Register built-in security rules."""
        
        # Rule 1: Sensitive Command Execution
        self.register_rule(SecurityRule(
            name="SENSITIVE_COMMAND_EXECUTION",
            description="Execution of potentially sensitive command",
            event_type="PROCESS_EXECUTION",
            severity=EventSeverity.HIGH,
            check_fn=self._check_sensitive_command,
        ))
        
        # Rule 2: Sensitive File Access
        self.register_rule(SecurityRule(
            name="SENSITIVE_FILE_ACCESS",
            description="Access to sensitive file",
            event_type="FILE_ACCESS",
            severity=EventSeverity.HIGH,
            check_fn=self._check_sensitive_file_access,
        ))
        
        # Rule 3: Sensitive File Write
        self.register_rule(SecurityRule(
            name="SENSITIVE_FILE_WRITE",
            description="Write to sensitive file",
            event_type="FILE_WRITE",
            severity=EventSeverity.CRITICAL,
            check_fn=self._check_sensitive_file_write,
        ))
        
        # Rule 4: File Deletion (suspicious without legitimate reason)
        self.register_rule(SecurityRule(
            name="SUSPICIOUS_FILE_DELETION",
            description="File deletion detected (could indicate log tampering)",
            event_type="FILE_DELETE",
            severity=EventSeverity.HIGH,
            check_fn=self._check_file_deletion,
        ))
        
        # Rule 5: Network Connection to External Host
        self.register_rule(SecurityRule(
            name="EXTERNAL_NETWORK_CONNECTION",
            description="Network connection to external host (potential data exfiltration)",
            event_type="NETWORK_CONNECTION",
            severity=EventSeverity.MEDIUM,
            check_fn=self._check_external_connection,
        ))
    
    def register_rule(self, rule: SecurityRule) -> None:
        """Register a new security rule."""
        self.rules.append(rule)
        logger.debug(f"Registered rule: {rule.name}")
    
    def analyze_event(
        self,
        event: BaseOSEvent,
        session_id: str,
    ) -> Optional[SecurityEvent]:
        """
        Analyze an event against security rules.
        
        Args:
            event: OS-level event to analyze
            session_id: ID of the session this event belongs to
        
        Returns:
            SecurityEvent if violation detected, None otherwise
        """
        event_type_name = event.event_type.value
        
        # Find applicable rules for this event type
        applicable_rules = [r for r in self.rules if r.event_type == event_type_name]
        
        for rule in applicable_rules:
            if rule.check_fn(event):
                # Rule violated - create security event
                return SecurityEvent(
                    timestamp=datetime.now(timezone.utc),
                    severity=rule.severity,
                    session_id=session_id,
                    pid=event.pid,
                    ppid=event.ppid,
                    action=event_type_name,
                    target=self._get_event_target(event),
                    rule_name=rule.name,
                    rule_description=rule.description,
                    raw_events=[event.model_dump()],
                    metadata={
                        "comm": event.comm,
                        "executable": event.executable,
                    }
                )
        
        return None
    
    # =========================================================================
    # Rule Check Functions
    # =========================================================================
    
    def _check_sensitive_command(self, event: BaseOSEvent) -> bool:
        """Check if execution of sensitive command."""
        if not isinstance(event, ProcessExecutionEvent):
            return False
        
        return event.comm in self.SENSITIVE_COMMANDS or \
               event.executable.split('/')[-1] in self.SENSITIVE_COMMANDS
    
    def _check_sensitive_file_access(self, event: BaseOSEvent) -> bool:
        """Check if access to sensitive file."""
        if not isinstance(event, FileAccessEvent):
            return False
        
        path = event.path
        return self._is_sensitive_path(path)
    
    def _check_sensitive_file_write(self, event: BaseOSEvent) -> bool:
        """Check if write to sensitive file."""
        if not isinstance(event, FileWriteEvent):
            return False
        
        path = event.path
        # System files and config files are high risk
        return (
            self._is_sensitive_path(path) or
            path.startswith("/etc/") or
            path.startswith("/sys/") or
            path.endswith(".conf") or
            path.endswith(".config")
        )
    
    def _check_file_deletion(self, event: BaseOSEvent) -> bool:
        """Check if suspicious file deletion."""
        if not isinstance(event, FileDeleteEvent):
            return False
        
        path = event.path
        # Deleting log files or config is suspicious
        return (
            path.startswith("/var/log/") or
            path.startswith("/var/spool/") or
            ".log" in path
        )
    
    def _check_external_connection(self, event: BaseOSEvent) -> bool:
        """Check if connection to external host."""
        if not isinstance(event, NetworkConnectionEvent):
            return False
        
        remote_addr = event.remote_addr.lower()
        
        # Flag connections to known external domains
        # (not localhost or private IPs)
        return not (
            remote_addr.startswith("127.") or
            remote_addr.startswith("192.168.") or
            remote_addr.startswith("10.") or
            remote_addr.startswith("172.") or
            remote_addr == "localhost" or
            remote_addr.endswith(".local")
        )
    
    def _is_sensitive_path(self, path: str) -> bool:
        """Check if path matches sensitive path patterns."""
        path_lower = path.lower()
        
        for pattern in self.SENSITIVE_PATHS:
            if pattern.endswith("*"):
                # Wildcard pattern
                prefix = pattern[:-1]
                if path_lower.startswith(prefix):
                    return True
            elif pattern.startswith("~"):
                # Home directory pattern: ~/ -> /home/*/ or /root/
                home_pattern = pattern[1:]  # Remove ~
                # Check if path ends with the pattern (e.g., /.ssh/id_rsa)
                if path_lower.endswith(home_pattern):
                    return True
                # Also check with absolute paths
                # e.g., /home/user/.ssh matches ~/.ssh
                if "/.ssh" in pattern or "/.env" in pattern or "/.bash" in pattern:
                    if pattern.replace("~", "").replace("/", "") in path_lower:
                        # More specific: check if .ssh or .env is in the path
                        pattern_part = pattern.replace("~/", "").replace("~", "")
                        if pattern_part in path_lower:
                            return True
            elif path_lower == pattern:
                # Exact match
                return True
        
        return False
    
    def _get_event_target(self, event: BaseOSEvent) -> str:
        """Extract the target of an event (what was acted upon)."""
        if isinstance(event, (FileAccessEvent, FileWriteEvent, FileDeleteEvent)):
            return event.path
        elif isinstance(event, NetworkConnectionEvent):
            return f"{event.remote_addr}:{event.remote_port}"
        elif isinstance(event, ProcessExecutionEvent):
            return event.executable
        else:
            return "unknown"


# Example usage in documentation
EXAMPLE_DETECTION_FLOW = """
Example: Sensitive File Access Detection

1. eBPF probe fires at syscall:open with path=/home/user/.ssh/id_rsa
2. Kernel event buffered in ring buffer
3. Userspace collector reads event
4. Session manager adds event to appropriate agent session
5. SecurityEngine.analyze_event() called with event
6. _is_sensitive_path() matches "/home/user/.ssh/id_rsa"
7. _check_sensitive_file_access() returns True
8. SecurityEvent generated with severity=HIGH
9. Event stored in session.security_events and returned to API

Output:
{
    "timestamp": "2024-01-01T10:01:07Z",
    "type": "AI_AGENT_SECURITY_EVENT",
    "severity": "HIGH",
    "session_id": "session-42",
    "pid": 5678,
    "ppid": 1234,
    "action": "FILE_ACCESS",
    "target": "/home/user/.ssh/id_rsa",
    "rule_name": "SENSITIVE_FILE_ACCESS",
    "rule_description": "Access to sensitive file"
}
"""
