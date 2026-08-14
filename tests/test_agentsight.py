"""
Unit tests for AgentSight system.

Tests cover:
- Event model creation and validation
- Session management
- Security rule detection
- API endpoints
"""

import pytest
from datetime import datetime, timezone, timedelta

from src.models import (
    ProcessExecutionEvent,
    FileAccessEvent,
    FileDeleteEvent,
    NetworkConnectionEvent,
    SecurityEvent,
    EventSeverity,
    AgentSession,
    ProcessNode,
)
from src.collector.collector import BPFEventCollector, SessionManager
from src.collector.security import SecurityEngine


# =============================================================================
# Tests: Event Models
# =============================================================================

class TestEventModels:
    """Test event model creation and validation."""
    
    def test_process_execution_event_creation(self):
        """Test creating a process execution event."""
        event = ProcessExecutionEvent(
            timestamp=datetime.now(timezone.utc),
            pid=1234,
            ppid=1000,
            uid=1000,
            gid=1000,
            comm="curl",
            executable="/usr/bin/curl",
            argv=["curl", "https://example.com"],
        )
        
        assert event.pid == 1234
        assert event.comm == "curl"
        assert event.executable == "/usr/bin/curl"
        assert len(event.argv) == 2
    
    def test_security_event_creation(self):
        """Test creating a security event."""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            severity=EventSeverity.HIGH,
            session_id="session-1",
            pid=1234,
            ppid=1000,
            action="FILE_ACCESS",
            target="/home/user/.ssh/id_rsa",
            rule_name="SENSITIVE_FILE_ACCESS",
            rule_description="Access to sensitive file",
        )
        
        assert event.severity == EventSeverity.HIGH
        assert event.action == "FILE_ACCESS"
        assert event.target == "/home/user/.ssh/id_rsa"


# =============================================================================
# Tests: Session Management
# =============================================================================

class TestSessionManagement:
    """Test agent session creation and management."""

    def test_ebpf_probe_preflight_reports_kernel_status(self):
        """Kernel injection checks should report a clear eBPF readiness status."""
        collector = BPFEventCollector()

        status = collector.check_kernel_injection_capabilities()

        assert isinstance(status, dict)
        assert "platform" in status
        assert "kernel_version" in status
        assert "bpf_supported" in status
        assert "injected" in status
        assert "reason" in status

    def test_start_refuses_when_kernel_injection_is_unavailable(self, monkeypatch):
        """start() should not mark the collector as running if eBPF injection fails."""
        collector = BPFEventCollector()
        monkeypatch.setattr(
            collector,
            "_load_kernel_probe",
            lambda: {"injected": False, "reason": "requires CAP_BPF"},
        )

        collector.start()

        assert collector.is_running is False
        assert collector.last_load_status["injected"] is False

    def test_create_session(self):
        """Test creating a new session."""
        manager = SessionManager()
        
        event = ProcessExecutionEvent(
            timestamp=datetime.now(timezone.utc),
            pid=1234,
            ppid=1000,
            uid=1000,
            gid=1000,
            comm="python",
            executable="/usr/bin/python3",
        )
        
        session = manager.create_session(
            session_id="test-session",
            agent_name="test-agent",
            initial_event=event,
        )
        
        assert session.session_id == "test-session"
        assert session.agent_name == "test-agent"
        assert session.main_pid == 1234
        assert len(session.processes) == 1
    
    def test_add_child_process(self):
        """Test adding child process to session."""
        manager = SessionManager()
        
        parent_event = ProcessExecutionEvent(
            timestamp=datetime.now(timezone.utc),
            pid=1000,
            ppid=500,
            uid=1000,
            gid=1000,
            comm="python",
            executable="/usr/bin/python3",
        )
        
        session = manager.create_session(
            session_id="test",
            agent_name="test",
            initial_event=parent_event,
        )
        
        child_event = ProcessExecutionEvent(
            timestamp=datetime.now(timezone.utc),
            pid=1001,
            ppid=1000,  # Child of parent
            uid=1000,
            gid=1000,
            comm="curl",
            executable="/usr/bin/curl",
        )
        
        manager.add_event_to_session("test", child_event)
        
        assert 1001 in session.processes
        assert 1001 in session.processes[1000].children_pids
    
    def test_process_tree_building(self):
        """Test building process tree."""
        manager = SessionManager()
        now = datetime.now(timezone.utc)
        
        # Parent process
        parent = ProcessExecutionEvent(
            timestamp=now,
            pid=1000, ppid=500, uid=1000, gid=1000,
            comm="python", executable="/usr/bin/python3",
        )
        
        session = manager.create_session("test", "agent", parent)
        
        # Add children
        for i in range(3):
            child = ProcessExecutionEvent(
                timestamp=now + timedelta(seconds=i),
                pid=1001+i, ppid=1000, uid=1000, gid=1000,
                comm=f"child{i}", executable=f"/bin/child{i}",
            )
            manager.add_event_to_session("test", child)
        
        tree = session.get_process_tree()
        assert tree["pid"] == 1000
        assert len(tree["children"]) == 3
    
    def test_session_summary(self):
        """Test session summary generation."""
        manager = SessionManager()
        now = datetime.now(timezone.utc)
        
        parent = ProcessExecutionEvent(
            timestamp=now, pid=1000, ppid=500, uid=1000, gid=1000,
            comm="python", executable="/usr/bin/python3",
        )
        
        session = manager.create_session("test", "agent", parent)
        
        # Add events
        for i in range(5):
            child = ProcessExecutionEvent(
                timestamp=now + timedelta(seconds=i),
                pid=1001+i, ppid=1000, uid=1000, gid=1000,
                comm=f"proc{i}", executable=f"/bin/proc{i}",
            )
            manager.add_event_to_session("test", child)
        
        summary = session.get_summary()
        assert summary.total_processes == 6  # 1 parent + 5 children
        assert summary.total_events == 6


# =============================================================================
# Tests: Security Rules
# =============================================================================

class TestSecurityRules:
    """Test security rule detection."""
    
    def test_sensitive_command_detection(self):
        """Test detection of sensitive command execution."""
        engine = SecurityEngine()
        
        event = ProcessExecutionEvent(
            timestamp=datetime.now(timezone.utc),
            pid=1234, ppid=1000, uid=1000, gid=1000,
            comm="curl",
            executable="/usr/bin/curl",
        )
        
        sec_event = engine.analyze_event(event, "session-1")
        assert sec_event is not None
        assert sec_event.rule_name == "SENSITIVE_COMMAND_EXECUTION"
        assert sec_event.severity == EventSeverity.HIGH
    
    def test_sensitive_file_access_detection(self):
        """Test detection of sensitive file access."""
        engine = SecurityEngine()
        
        event = FileAccessEvent(
            timestamp=datetime.now(timezone.utc),
            pid=1234, ppid=1000, uid=1000, gid=1000,
            comm="python", executable="/usr/bin/python3",
            path="/home/user/.ssh/id_rsa",
        )
        
        sec_event = engine.analyze_event(event, "session-1")
        assert sec_event is not None
        assert sec_event.rule_name == "SENSITIVE_FILE_ACCESS"
        assert sec_event.severity == EventSeverity.HIGH
    
    def test_normal_file_access_no_alert(self):
        """Test that normal file access doesn't trigger alert."""
        engine = SecurityEngine()
        
        event = FileAccessEvent(
            timestamp=datetime.now(timezone.utc),
            pid=1234, ppid=1000, uid=1000, gid=1000,
            comm="cat", executable="/bin/cat",
            path="/tmp/myfile.txt",
        )
        
        sec_event = engine.analyze_event(event, "session-1")
        assert sec_event is None
    
    def test_file_deletion_detection(self):
        """Test detection of file deletion."""
        engine = SecurityEngine()
        
        event = FileDeleteEvent(
            timestamp=datetime.now(timezone.utc),
            pid=1234, ppid=1000, uid=1000, gid=1000,
            comm="rm", executable="/bin/rm",
            path="/var/log/auth.log",
        )
        
        sec_event = engine.analyze_event(event, "session-1")
        assert sec_event is not None
        assert sec_event.rule_name == "SUSPICIOUS_FILE_DELETION"
    
    def test_external_network_connection_detection(self):
        """Test detection of external network connections."""
        engine = SecurityEngine()
        
        event = NetworkConnectionEvent(
            timestamp=datetime.now(timezone.utc),
            pid=1234, ppid=1000, uid=1000, gid=1000,
            comm="curl", executable="/usr/bin/curl",
            remote_addr="external-host.com",
            remote_port=443,
        )
        
        sec_event = engine.analyze_event(event, "session-1")
        assert sec_event is not None
        assert sec_event.rule_name == "EXTERNAL_NETWORK_CONNECTION"


# =============================================================================
# Run tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
