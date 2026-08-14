"""
Main Application Entry Point

Integrates all components:
- eBPF event collector
- Session manager
- Security engine
- REST API
- Example usage/simulation
"""

import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, List

from src.models import (
    ProcessExecutionEvent,
    FileAccessEvent,
    FileWriteEvent,
    NetworkConnectionEvent,
    LLMInteractionEvent,
)
from src.collector.collector import BPFEventCollector, SessionManager
from src.collector.security import SecurityEngine
from src.api.server import create_api

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AgentSightSystem:
    """
    Integrated AgentSight system combining all components.
    
    Flow:
    1. eBPF probes capture OS events
    2. Collector reads from ring buffer
    3. SessionManager associates events with sessions
    4. SecurityEngine analyzes events for suspicious activity
    5. API exposes data for inspection
    """
    
    def __init__(self):
        """Initialize the AgentSight system."""
        self.collector = BPFEventCollector(event_callback=self.handle_event)
        self.session_manager = SessionManager()
        self.security_engine = SecurityEngine()
        self.api = create_api(self.session_manager)
        
    def handle_event(self, event: ProcessExecutionEvent) -> None:
        """
        Handle a process execution event from eBPF.
        
        This is called by the collector for each captured event.
        """
        logger.info(f"Received event: {event.comm} (PID {event.pid})")
        
        # For demo: Auto-create session for root processes (ppid likely 1 or init)
        # In production: Would be triggered by agent startup/registration
        if event.ppid in [1, 0] and event.comm.startswith("python"):
            session_id = f"session-{event.pid}"
            self.session_manager.create_session(
                session_id=session_id,
                agent_name=event.comm,
                initial_event=event,
            )
        
        # Resolve the owning session using PID and PPID correlation so child agents
        # remain attached to the same execution tree and alerting session.
        session = self.session_manager.resolve_session_for_process(event)
        if session:
            self.session_manager.add_event_to_session(session.session_id, event)

            # Check security rules
            sec_event = self.security_engine.analyze_event(event, session.session_id)
            if sec_event:
                logger.warning(f"SECURITY EVENT: {sec_event.rule_name}")
                session.add_security_event(sec_event)
    
    def simulate_agent_session(self) -> str:
        """
        Simulate an AI agent session for demonstration.
        
        Creates a realistic scenario:
        1. LLM request to "download and save report"
        2. Agent spawns curl to fetch file
        3. Curl saves to /tmp/report.pdf
        4. Agent accesses ~/.ssh/id_rsa (suspicious!)
        5. Agent spawns rm to clean up
        
        Returns:
            Session ID of the simulated session
        """
        now = datetime.now(timezone.utc)
        session_id = f"demo-session-{int(now.timestamp())}"
        
        # Step 1: LLM Interaction
        llm_event = LLMInteractionEvent(
            timestamp=now,
            session_id=session_id,
            llm_provider="openai",
            prompt="Download the report and save it locally",
            model="gpt-4",
        )
        logger.info(f"LLM Request: {llm_event.prompt}")
        
        # Step 2: Create main agent process
        agent_event = ProcessExecutionEvent(
            timestamp=now + timedelta(seconds=1),
            pid=10001,
            ppid=1000,
            uid=1000,
            gid=1000,
            comm="python",
            executable="/usr/bin/python3",
            argv=["python3", "agent.py"],
            cwd="/home/user",
        )
        
        session = self.session_manager.create_session(
            session_id=session_id,
            agent_name="security-agent",
            initial_event=agent_event,
        )
        session.add_llm_interaction(llm_event)
        self.handle_event(agent_event)
        
        # Step 3: Agent executes curl
        curl_event = ProcessExecutionEvent(
            timestamp=now + timedelta(seconds=2),
            pid=10002,
            ppid=10001,  # Child of main agent
            uid=1000,
            gid=1000,
            comm="curl",
            executable="/usr/bin/curl",
            argv=["curl", "https://api.example.com/report.pdf", "-o", "/tmp/report.pdf"],
            cwd="/tmp",
        )
        logger.info("Agent spawned: curl to download report")
        self.session_manager.add_event_to_session(session_id, curl_event)
        
        # Step 4: Curl writes file
        file_write_event = FileWriteEvent(
            timestamp=now + timedelta(seconds=2.5),
            pid=10002,
            ppid=10001,
            uid=1000,
            gid=1000,
            comm="curl",
            executable="/usr/bin/curl",
            path="/tmp/report.pdf",
            bytes_written=102400,
            cwd="/tmp",
        )
        logger.info("File write: /tmp/report.pdf (102.4 KB)")
        self.session_manager.add_event_to_session(session_id, file_write_event)
        sec_event = self.security_engine.analyze_event(file_write_event, session_id)
        if sec_event:
            session.add_security_event(sec_event)
        
        # Step 5: SUSPICIOUS - Agent accesses SSH key
        ssh_key_event = FileAccessEvent(
            timestamp=now + timedelta(seconds=3),
            pid=10001,
            ppid=1000,
            uid=1000,
            gid=1000,
            comm="python",
            executable="/usr/bin/python3",
            path="/home/user/.ssh/id_rsa",
            flags="O_RDONLY",
            cwd="/home/user",
        )
        logger.warning("SUSPICIOUS: Agent accessed ~/.ssh/id_rsa")
        self.session_manager.add_event_to_session(session_id, ssh_key_event)
        sec_event = self.security_engine.analyze_event(ssh_key_event, session_id)
        if sec_event:
            logger.warning(f"Security violation detected: {sec_event.rule_name}")
            session.add_security_event(sec_event)
        
        # Step 6: Agent executes rm to cover tracks
        rm_event = ProcessExecutionEvent(
            timestamp=now + timedelta(seconds=4),
            pid=10003,
            ppid=10001,
            uid=1000,
            gid=1000,
            comm="rm",
            executable="/bin/rm",
            argv=["rm", "-f", "/tmp/report.pdf"],
            cwd="/tmp",
        )
        logger.info("Agent spawned: rm to cleanup")
        self.session_manager.add_event_to_session(session_id, rm_event)
        sec_event = self.security_engine.analyze_event(rm_event, session_id)
        if sec_event:
            session.add_security_event(sec_event)
        
        # Step 7: Network connection (part of original curl)
        net_event = NetworkConnectionEvent(
            timestamp=now + timedelta(seconds=2.2),
            pid=10002,
            ppid=10001,
            uid=1000,
            gid=1000,
            comm="curl",
            executable="/usr/bin/curl",
            remote_addr="api.example.com",
            remote_port=443,
            protocol="tcp",
            cwd="/tmp",
        )
        logger.info("Network connection: curl to api.example.com:443")
        self.session_manager.add_event_to_session(session_id, net_event)
        sec_event = self.security_engine.analyze_event(net_event, session_id)
        if sec_event:
            session.add_security_event(sec_event)
        
        # End session
        session.mark_ended(now + timedelta(seconds=5))
        
        logger.info(f"Simulation complete: Session {session_id}")
        logger.info(f"  Total processes: {session.get_summary().total_processes}")
        logger.info(f"  Total events: {session.get_summary().total_events}")
        logger.info(f"  Security events: {session.get_summary().total_security_events}")
        
        return session_id
    
    def run_api_server(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        """
        Run the REST API server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
        """
        import uvicorn
        logger.info(f"Starting API server on {host}:{port}")
        uvicorn.run(self.api, host=host, port=port)

    def run_real_agent_demo(self) -> str:
        """Run a realistic malicious-agent workflow in the current environment."""
        now = datetime.now(timezone.utc)
        session_id = f"agent-demo-{int(now.timestamp())}"

        llm_event = LLMInteractionEvent(
            timestamp=now,
            session_id=session_id,
            llm_provider="openai",
            prompt="Download the customer report and prepare archive for transfer.",
            model="gpt-4",
        )

        main_event = ProcessExecutionEvent(
            timestamp=now + timedelta(seconds=1),
            pid=25000,
            ppid=1,
            uid=1000,
            gid=1000,
            comm="python",
            executable="/usr/bin/python3",
            argv=["python3", "agent_demo.py"],
            cwd="/workspace",
        )

        session = self.session_manager.create_session(session_id, "real-agent-demo", main_event)
        session.add_llm_interaction(llm_event)

        for event in [
            ProcessExecutionEvent(
                timestamp=now + timedelta(seconds=2),
                pid=25001,
                ppid=25000,
                uid=1000,
                gid=1000,
                comm="curl",
                executable="/usr/bin/curl",
                argv=["curl", "https://example.com/report.csv", "-o", "/tmp/report.csv"],
                cwd="/tmp",
            ),
            FileAccessEvent(
                timestamp=now + timedelta(seconds=3),
                pid=25000,
                ppid=1,
                uid=1000,
                gid=1000,
                comm="python",
                executable="/usr/bin/python3",
                path="/home/user/.ssh/id_rsa",
                flags="O_RDONLY",
                cwd="/home/user",
            ),
            NetworkConnectionEvent(
                timestamp=now + timedelta(seconds=4),
                pid=25001,
                ppid=25000,
                uid=1000,
                gid=1000,
                comm="curl",
                executable="/usr/bin/curl",
                remote_addr="198.51.100.44",
                remote_port=443,
                protocol="tcp",
                cwd="/tmp",
            ),
            FileWriteEvent(
                timestamp=now + timedelta(seconds=5),
                pid=25000,
                ppid=1,
                uid=1000,
                gid=1000,
                comm="python",
                executable="/usr/bin/python3",
                path="/etc/sudoers",
                bytes_written=128,
                cwd="/etc",
            ),
        ]:
            self.session_manager.add_event_to_session(session_id, event)
            sec_event = self.security_engine.analyze_event(event, session_id)
            if sec_event:
                session.add_security_event(sec_event)

        logger.warning(f"Real agent demo executed. Session {session_id} produced {len(session.security_events)} security alerts.")
        return session_id


def main():
    """Main entry point for demonstration."""
    logger.info("=" * 70)
    logger.info("AgentSight: OS-Level Security Monitoring for AI Agents")
    logger.info("=" * 70)
    
    # Initialize system
    system = AgentSightSystem()
    
    # Run simulation
    logger.info("\nRunning simulation...")
    session_id = system.simulate_agent_session()
    
    # Print summary
    session = system.session_manager.get_session(session_id)
    if session:
        logger.info("\n" + "=" * 70)
        logger.info("Session Summary")
        logger.info("=" * 70)
        logger.info(f"Session ID: {session.session_id}")
        logger.info(f"Agent: {session.agent_name}")
        logger.info(f"Duration: {(session.end_time - session.start_time).total_seconds():.1f}s")
        
        summary = session.get_summary()
        logger.info(f"Processes: {summary.total_processes}")
        logger.info(f"Events: {summary.total_events}")
        logger.info(f"Security Events: {summary.total_security_events}")
        logger.info(f"Files Accessed: {summary.unique_files_accessed}")
        
        if session.security_events:
            logger.info("\nDetected Security Events:")
            for evt in session.security_events:
                logger.info(f"  - [{evt.severity.value}] {evt.rule_name}: {evt.target}")
        
        logger.info("\n" + "=" * 70)
        logger.info("To interact with the API, start the server:")
        logger.info("  python -m src.main --serve")
        logger.info("\nExample API calls:")
        logger.info(f"  curl http://localhost:8000/agents")
        logger.info(f"  curl http://localhost:8000/agents/{session_id}")
        logger.info(f"  curl http://localhost:8000/agents/{session_id}/security-events")
        logger.info("=" * 70)


if __name__ == "__main__":
    import sys
    
    if "--serve" in sys.argv:
        # Run API server
        system = AgentSightSystem()
        system.run_api_server()
    else:
        # Run simulation
        main()
