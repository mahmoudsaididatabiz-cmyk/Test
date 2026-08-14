"""
OPTIMIZED Security Rules Engine - Advanced Version

Part D ENHANCED: Detect suspicious/sensitive actions performed by AI agents.

This module implements 10+ security rules with:
- Pattern matching cache (O(1) lookups)
- Behavioral anomaly detection
- Context-aware rules
- Attack pattern recognition

Rules implemented:
1. Sensitive Command Execution
2. Sensitive File Access
3. Sensitive File Write (CRITICAL)
4. File Deletion / Log Tampering
5. External Network Connection
6. Privilege Escalation Attempts
7. Credential Theft Detection
8. Process Spawning Chain (fork bomb)
9. Rapid Connection Pattern (data exfiltration)
10. System Config Modification
11. Environment Variable Injection
12. Suspicious Process Naming
"""

import logging
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set, Callable
from dataclasses import dataclass
from collections import defaultdict

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
    enabled: bool = True


class SecurityEngine:
    """
    ENHANCED Part D: Security detection engine.
    
    Analyzes OS events and detects potentially sensitive actions.
    Emits SecurityEvent when a rule is violated.
    
    Algorithmic Optimizations:
    - Pattern matching cache with pre-compiled regexes
    - O(1) command name lookup via set membership
    - Context-aware rules (distinguishes root vs. unprivileged)
    - Behavioral state tracking (repeated violations)
    - Time-windowed anomaly detection
    """
    
    # =========================================================================
    # Sensitive Commands (SET for O(1) lookup)
    # =========================================================================
    
    SENSITIVE_COMMANDS = {
        # Network tools (data exfiltration risk)
        "curl", "wget", "nc", "ncat", "netcat",
        "ssh", "scp", "sftp", "rsync",
        "telnet", "socat",
        
        # File transfer
        "ftp", "lftp",
        
        # Package/privilege escalation
        "sudo", "su", "runas",
        
        # File operations
        "chmod", "chown", "chgrp",
        "rm", "shred", "srm",  # Destructive ops
        "dd",  # Low-level disk access
        
        # Version control (can exfiltrate data via git push)
        "git", "svn", "hg",
        
        # Crypto/security
        "gpg", "openssl", "ssh-keygen",
        
        # Scripting/execution
        "perl", "ruby", "python", "node", "php",
        
        # Shell
        "bash", "sh", "zsh", "ksh",
        
        # Package managers
        "pip", "npm", "gem", "apt", "yum", "brew",
    }
    
    # Sensitive file paths (using set for O(1) lookup where exact)
    SENSITIVE_PATHS_EXACT = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/gshadow",
        "/root/.ssh",
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "/.ssh",
        "/.env",
        "/.aws",
        "/.kube",
        "/proc/sched_debug",
        "/proc/keys",
        "/home/user/.netrc",
        "/root/.netrc",
    }
    
    # Patterns for regex matching (compiled for performance)
    SENSITIVE_PATTERNS = [
        re.compile(r"/root/\.ssh/.*"),
        re.compile(r"/home/[^/]+/\.ssh/.*"),  # User SSH keys
        re.compile(r"/home/[^/]+/\.env"),     # User .env files
        re.compile(r"/home/[^/]+/\.aws/.*"),  # AWS credentials
        re.compile(r"/home/[^/]+/\.kube/.*"), # Kubernetes config
        re.compile(r"/home/[^/]+/\.netrc"),
        re.compile(r"/home/[^/]+/\.bash_history"),  # Bash history
        re.compile(r"/root/\.netrc"),
        re.compile(r"/var/log/.*"),           # Log files
        re.compile(r"/var/spool/.*"),         # Spool files
        re.compile(r"/etc/.*\.conf"),         # Config files
    ]
    
    def __init__(self):
        """Initialize the security engine with all detection rules."""
        self.rules: List[SecurityRule] = []
        
        # Behavioral state tracking (for anomaly detection)
        self.session_connection_history: Dict[str, List[datetime]] = defaultdict(list)
        self.session_spawn_history: Dict[str, List[datetime]] = defaultdict(list)
        self.session_file_access_history: Dict[str, List[str]] = defaultdict(list)
        
        # Regex cache (avoid recompiling)
        self.regex_cache: Dict[str, re.Pattern] = {}
        
        self._register_default_rules()
    
    def _register_default_rules(self) -> None:
        """Register built-in security rules."""
        
        # ===== Rule 1: Sensitive Command Execution =====
        self.register_rule(SecurityRule(
            name="SENSITIVE_COMMAND_EXECUTION",
            description="Execution of potentially sensitive command",
            event_type="PROCESS_EXECUTION",
            severity=EventSeverity.HIGH,
            check_fn=self._check_sensitive_command,
        ))
        
        # ===== Rule 2: Sensitive File Access =====
        self.register_rule(SecurityRule(
            name="SENSITIVE_FILE_ACCESS",
            description="Access to sensitive file",
            event_type="FILE_ACCESS",
            severity=EventSeverity.HIGH,
            check_fn=self._check_sensitive_file_access,
        ))
        
        # ===== Rule 3: Sensitive File Write (CRITICAL) =====
        self.register_rule(SecurityRule(
            name="SENSITIVE_FILE_WRITE",
            description="Write to sensitive file (system modification)",
            event_type="FILE_WRITE",
            severity=EventSeverity.CRITICAL,
            check_fn=self._check_sensitive_file_write,
        ))
        
        # ===== Rule 4: Suspicious File Deletion =====
        self.register_rule(SecurityRule(
            name="SUSPICIOUS_FILE_DELETION",
            description="File deletion detected (log tampering, evidence destruction)",
            event_type="FILE_DELETE",
            severity=EventSeverity.HIGH,
            check_fn=self._check_file_deletion,
        ))
        
        # ===== Rule 5: External Network Connection =====
        self.register_rule(SecurityRule(
            name="EXTERNAL_NETWORK_CONNECTION",
            description="Network connection to external host (potential data exfiltration)",
            event_type="NETWORK_CONNECTION",
            severity=EventSeverity.MEDIUM,
            check_fn=self._check_external_connection,
        ))
        
        # ===== Rule 6: Privilege Escalation =====
        self.register_rule(SecurityRule(
            name="PRIVILEGE_ESCALATION_ATTEMPT",
            description="Attempt to escalate privileges (sudo, chmod 777, etc.)",
            event_type="PROCESS_EXECUTION",
            severity=EventSeverity.CRITICAL,
            check_fn=self._check_privilege_escalation,
        ))
        
        # ===== Rule 7: Credential Access =====
        self.register_rule(SecurityRule(
            name="CREDENTIAL_THEFT_ATTEMPT",
            description="Attempts to access credential storage (SSH keys, .env, AWS creds)",
            event_type="FILE_ACCESS",
            severity=EventSeverity.CRITICAL,
            check_fn=self._check_credential_access,
        ))
        
        # ===== Rule 8: Deep Process Spawning Chain =====
        self.register_rule(SecurityRule(
            name="EXCESSIVE_PROCESS_SPAWNING",
            description="Excessive child process spawning (fork bomb / DoS pattern)",
            event_type="PROCESS_EXECUTION",
            severity=EventSeverity.HIGH,
            check_fn=self._check_excessive_spawning,
        ))
        
        # ===== Rule 9: System Configuration Modification =====
        self.register_rule(SecurityRule(
            name="SYSTEM_CONFIG_MODIFICATION",
            description="Modification of critical system configuration files",
            event_type="FILE_WRITE",
            severity=EventSeverity.CRITICAL,
            check_fn=self._check_config_modification,
        ))
        
        # ===== Rule 10: Rapid Network Connections =====
        self.register_rule(SecurityRule(
            name="RAPID_NETWORK_PATTERN",
            description="Rapid connection pattern (data exfiltration, C2 communication)",
            event_type="NETWORK_CONNECTION",
            severity=EventSeverity.MEDIUM,
            check_fn=self._check_rapid_connections,
        ))
        
        # ===== Rule 11: Environment Variable Injection =====
        self.register_rule(SecurityRule(
            name="ENVIRONMENT_INJECTION",
            description="Process execution with suspicious environment variables",
            event_type="PROCESS_EXECUTION",
            severity=EventSeverity.MEDIUM,
            check_fn=self._check_env_injection,
        ))
        
        # ===== Rule 12: Suspicious Process Naming =====
        self.register_rule(SecurityRule(
            name="SUSPICIOUS_PROCESS_NAME",
            description="Process with suspicious naming pattern (malware indicators)",
            event_type="PROCESS_EXECUTION",
            severity=EventSeverity.HIGH,
            check_fn=self._check_suspicious_naming,
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
        
        O(1) to O(n) depending on event type:
        - Most rules: O(1) set/dict lookup
        - Some: O(n) pattern matching or state lookup
        
        Args:
            event: OS-level event to analyze
            session_id: ID of the session this event belongs to
        
        Returns:
            SecurityEvent if violation detected, None otherwise
        """
        event_type_name = event.event_type.value
        
        # Find applicable rules for this event type
        applicable_rules = [r for r in self.rules 
                          if r.event_type == event_type_name and r.enabled]
        
        triggered = []
        for rule in applicable_rules:
            try:
                if rule.check_fn(event, session_id):
                    triggered.append(rule)
            except Exception as e:
                logger.error(f"Error checking rule {rule.name}: {e}", exc_info=True)

        if not triggered:
            return None

        # Prefer the most specific rule for a given event family before falling back to severity.
        priority_order = [
            "PRIVILEGE_ESCALATION_ATTEMPT",
            "SENSITIVE_FILE_WRITE",
            "SENSITIVE_COMMAND_EXECUTION",
            "SENSITIVE_FILE_ACCESS",
            "CREDENTIAL_THEFT_ATTEMPT",
            "SUSPICIOUS_FILE_DELETION",
            "EXTERNAL_NETWORK_CONNECTION",
            "SYSTEM_CONFIG_MODIFICATION",
            "ENVIRONMENT_INJECTION",
            "SUSPICIOUS_PROCESS_NAME",
            "EXCESSIVE_PROCESS_SPAWNING",
            "RAPID_NETWORK_PATTERN",
        ]

        score_map = {
            EventSeverity.LOW: 1,
            EventSeverity.MEDIUM: 2,
            EventSeverity.HIGH: 3,
            EventSeverity.CRITICAL: 4,
        }

        def rule_rank(rule):
            priority = priority_order.index(rule.name) if rule.name in priority_order else len(priority_order)
            return (priority, score_map.get(rule.severity, 0))

        best_rule = min(triggered, key=rule_rank)

        return SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            severity=best_rule.severity,
            session_id=session_id,
            pid=event.pid,
            ppid=event.ppid,
            action=event_type_name,
            target=self._get_event_target(event),
            rule_name=best_rule.name,
            rule_description=best_rule.description,
            raw_events=[event.model_dump(mode="json")],
            metadata={
                "comm": event.comm,
                "executable": event.executable,
            }
        )
    
    # =========================================================================
    # Rule Check Functions (optimized algorithms)
    # =========================================================================
    
    def _check_sensitive_command(self, event: BaseOSEvent, session_id: str = "") -> bool:
        """
        O(1) Check if execution of sensitive command.
        """
        if not isinstance(event, ProcessExecutionEvent):
            return False
        
        # Set membership is O(1)
        comm_name = event.comm.split('/')[-1]  # Get basename
        return comm_name in self.SENSITIVE_COMMANDS or \
               event.executable.split('/')[-1] in self.SENSITIVE_COMMANDS
    
    def _check_sensitive_file_access(self, event: BaseOSEvent, session_id: str = "") -> bool:
        """
        O(1) + O(n) Check if access to sensitive file.
        """
        if not isinstance(event, FileAccessEvent):
            return False
        
        return self._is_sensitive_path(event.path)
    
    def _check_sensitive_file_write(self, event: BaseOSEvent, session_id: str = "") -> bool:
        """
        O(1) Check if write to sensitive file.
        """
        if not isinstance(event, FileWriteEvent):
            return False
        
        path = event.path.lower()
        
        # System files and critical config files are HIGH RISK
        return (
            self._is_sensitive_path(event.path) or
            path.startswith("/etc/") or
            path.startswith("/sys/") or
            path.startswith("/proc/") or
            ".conf" in path or
            ".config" in path or
            ".json" in path and "/etc/" in path
        )
    
    def _check_file_deletion(self, event: BaseOSEvent, session_id: str = "") -> bool:
        """
        O(1) Check if suspicious file deletion.
        """
        if not isinstance(event, FileDeleteEvent):
            return False
        
        path = event.path.lower()
        
        # Deleting log files or config is suspicious
        return (
            "/var/log/" in path or
            "/var/spool/" in path or
            ".log" in path or
            ".bash_history" in path or
            path.endswith(".history")
        )
    
    def _check_external_connection(self, event: BaseOSEvent, session_id: str = "") -> bool:
        """
        O(1) Check if connection to external host.
        """
        if not isinstance(event, NetworkConnectionEvent):
            return False
        
        addr = event.remote_addr.lower()
        
        # Private IP ranges (no alert needed)
        private_ranges = [
            "127.",      # Loopback
            "192.168.",  # Private Class C
            "10.",       # Private Class A
            "172.1",     # Private Class B (172.16-172.31)
            "localhost",
        ]
        
        for prefix in private_ranges:
            if addr.startswith(prefix):
                return False
        
        # Also check for .local domains
        if addr.endswith(".local"):
            return False
        
        return True
    
    def _check_privilege_escalation(self, event: BaseOSEvent, session_id: str = "") -> bool:
        """
        O(1) Check for privilege escalation attempts.
        """
        if not isinstance(event, ProcessExecutionEvent):
            return False
        
        # Privilege escalation commands
        priv_escalation_commands = {"sudo", "su", "runas"}
        
        comm_name = event.comm.split('/')[-1]
        
        # Rule 1: Non-root using sudo/su
        if comm_name in priv_escalation_commands:
            # Check if non-root trying to escalate
            if event.uid != 0 and event.uid != 65534:  # Not root/nobody
                return True
        
        # Rule 2: chmod with dangerous permissions
        if comm_name == "chmod" and event.argv:
            for arg in event.argv:
                if "777" in arg or "+s" in arg:
                    return True
        
        return False
    
    def _check_credential_access(self, event: BaseOSEvent, session_id: str = "") -> bool:
        """
        O(1) + O(n) Check for attempts to access credentials.
        """
        if not isinstance(event, FileAccessEvent):
            return False
        
        path_lower = event.path.lower()
        
        # Direct credential storage locations
        credential_paths = [
            ".ssh/id_",      # SSH keys
            ".ssh/known_hosts",
            ".env",
            ".aws/credentials",
            ".aws/config",
            ".kube/config",
            ".netrc",
            ".docker/config.json",
            "/etc/shadow",
            "/etc/passwd",
        ]
        
        for cred_path in credential_paths:
            if cred_path in path_lower:
                return True
        
        return False
    
    def _check_excessive_spawning(self, event: BaseOSEvent, session_id: str = "") -> bool:
        """
        O(n) Check for excessive process spawning (fork bomb).
        """
        if not isinstance(event, ProcessExecutionEvent):
            return False
        
        # Track spawning history for this session
        self.session_spawn_history[session_id].append(datetime.now(timezone.utc))
        
        # Remove old entries (older than 10 seconds)
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=10)
        self.session_spawn_history[session_id] = [
            t for t in self.session_spawn_history[session_id] if t > cutoff
        ]
        
        # Alert if more than 50 processes spawned in 10 seconds
        return len(self.session_spawn_history[session_id]) > 50
    
    def _check_config_modification(self, event: BaseOSEvent, session_id: str = "") -> bool:
        """
        O(1) Check for system configuration modifications.
        """
        if not isinstance(event, FileWriteEvent):
            return False
        
        path = event.path.lower()
        
        # Critical system files - NO exceptions
        critical_files = [
            "/etc/sudoers",
            "/etc/shadow",
            "/etc/passwd",
            "/etc/group",
            "/root/.ssh",
            "/.ssh",
        ]
        
        for critical in critical_files:
            if critical in path:
                return True
        
        # Also flag writes to /etc/ generally with specific patterns
        if path.startswith("/etc/") and (".conf" in path or ".config" in path):
            return True
        
        return False
    
    def _check_rapid_connections(self, event: BaseOSEvent, session_id: str = "") -> bool:
        """
        O(n) Check for rapid connection pattern (exfiltration/C2).
        """
        if not isinstance(event, NetworkConnectionEvent):
            return False
        
        # Track connection history
        self.session_connection_history[session_id].append(datetime.now(timezone.utc))
        
        # Remove old entries (older than 5 seconds)
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=5)
        self.session_connection_history[session_id] = [
            t for t in self.session_connection_history[session_id] if t > cutoff
        ]
        
        # Alert if more than 10 connections in 5 seconds
        return len(self.session_connection_history[session_id]) > 10
    
    def _check_env_injection(self, event: BaseOSEvent, session_id: str = "") -> bool:
        """
        O(1) Check for environment variable injection.
        """
        if not isinstance(event, ProcessExecutionEvent):
            return False
        
        # Look for suspicious environment variables
        suspicious_vars = ["LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "IFS"]
        
        for var in suspicious_vars:
            if var in event.environ:
                # Check if value looks suspicious
                value = event.environ[var].lower()
                if "/tmp" in value or "/dev/shm" in value or "http" in value:
                    return True
        
        return False
    
    def _check_suspicious_naming(self, event: BaseOSEvent, session_id: str = "") -> bool:
        """
        O(1) Check for suspicious process naming patterns.
        """
        if not isinstance(event, ProcessExecutionEvent):
            return False
        
        comm_lower = event.comm.lower()
        
        # Common malware naming patterns
        suspicious_patterns = [
            "malware",
            "backdoor",
            "rat",
            "bot",
            "rootkit",
            "trojan",
            "worm",
            "loader",
            ".bin",
            ".exe",
        ]
        
        for pattern in suspicious_patterns:
            if pattern in comm_lower:
                return True
        
        # Also check for random-looking names (too short uppercase)
        if len(comm_lower) <= 4 and comm_lower.isupper() and not comm_lower in ["LS", "RM", "CP", "DD"]:
            return True
        
        return False
    
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    def _is_sensitive_path(self, path: str) -> bool:
        """
        O(1) + O(n) Check if path matches sensitive path patterns.
        Uses set for exact matches + regex for patterns.
        """
        path_lower = path.lower()
        
        # O(1) exact match check
        if path_lower in self.SENSITIVE_PATHS_EXACT:
            return True
        
        # O(n) regex pattern check (usually fast)
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern.match(path_lower):
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
    
    def get_detection_stats(self) -> Dict:
        """Get detection engine statistics."""
        return {
            "total_rules": len(self.rules),
            "enabled_rules": len([r for r in self.rules if r.enabled]),
            "sessions_tracked": len(self.session_connection_history),
            "regex_cache_size": len(self.regex_cache),
        }
