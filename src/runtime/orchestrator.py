"""
Unified AgentSight runtime orchestrator
Integrates: eBPF loader, persistence, policy engine, and collector
"""
import time
import logging
import json
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path

from src.runtime.ebpf_loader import EBPFProbeRuntime, KernelEvent
from src.runtime.persistence import EventStore, PersistedEvent, EventStreamer
from src.runtime.policy_engine import SecurityPolicyEngine, AlertRecord

logger = logging.getLogger(__name__)


class AgentSightRuntime:
    """
    Production runtime for AgentSight
    - Manages eBPF probe lifecycle
    - Persists events to SQLite
    - Evaluates security policies
    - Streams events and alerts
    """
    
    def __init__(
        self,
        ebpf_source: str,
        db_path: str = "/tmp/agentsight.db",
        policy_yaml: Optional[str] = None,
    ):
        self.ebpf_source = ebpf_source
        self.db_path = db_path
        self.policy_yaml = policy_yaml
        
        # Components
        self.probe_runtime: Optional[EBPFProbeRuntime] = None
        self.event_store: Optional[EventStore] = None
        self.policy_engine: Optional[SecurityPolicyEngine] = None
        self.streamer: Optional[EventStreamer] = None
        
        self._running = False
    
    def initialize(self) -> bool:
        """Initialize all runtime components"""
        logger.info("Initializing AgentSight runtime...")
        
        # 1. Initialize eBPF probe
        try:
            self.probe_runtime = EBPFProbeRuntime(self.ebpf_source)
            success = self.probe_runtime.compile_and_load()
            if not success:
                logger.warning("eBPF probe compilation failed; falling back to simulation")
            else:
                logger.info("✓ eBPF probe loaded")
        except Exception as e:
            logger.error(f"eBPF probe error: {e}")
            return False
        
        # 2. Initialize persistence
        try:
            self.event_store = EventStore(self.db_path)
            logger.info(f"✓ Event store: {self.db_path}")
        except Exception as e:
            logger.error(f"Event store error: {e}")
            return False
        
        # 3. Initialize policy engine
        try:
            self.policy_engine = SecurityPolicyEngine()
            if self.policy_yaml and Path(self.policy_yaml).exists():
                if not self.policy_engine.load_yaml_config(self.policy_yaml):
                    logger.warning("Failed to load policy config; using defaults")
            logger.info("✓ Policy engine ready")
        except Exception as e:
            logger.error(f"Policy engine error: {e}")
            return False
        
        # 4. Initialize event streamer
        try:
            self.streamer = EventStreamer()
            logger.info("✓ Event streamer initialized")
        except Exception as e:
            logger.error(f"Streamer error: {e}")
            return False
        
        logger.info("✓ All components initialized")
        return True
    
    def process_kernel_event(self, kernel_event: KernelEvent, agent_id: str = "") -> Dict[str, Any]:
        """
        Process single kernel event through full pipeline:
        1. Convert to persistent form
        2. Store in database
        3. Evaluate security policies
        4. Stream to handlers
        """
        # Convert kernel event to persistent form
        persist_event = PersistedEvent(
            timestamp_ns=kernel_event.timestamp_ns,
            event_type=kernel_event.event_type,
            pid=kernel_event.pid,
            ppid=kernel_event.ppid,
            uid=kernel_event.uid,
            gid=kernel_event.gid,
            comm=kernel_event.comm,
            data_json=json.dumps(kernel_event.data),
        )
        
        # Store event
        event_id = self.event_store.store_event(persist_event)
        logger.debug(f"Stored event {event_id}: {kernel_event.comm}")
        
        # Evaluate policies
        event_dict = persist_event.to_dict()
        event_dict['id'] = event_id
        event_dict['agent_id'] = agent_id
        
        alerts = self.policy_engine.evaluate_event(event_dict, agent_id)
        
        # Mark processed with violations
        violations = [alert.rule_name for alert in alerts]
        self.event_store.mark_processed(event_id, violations)
        
        # Stream alerts
        for alert in alerts:
            self._stream_alert(alert)
        
        return {
            'event_id': event_id,
            'alerts': [alert.to_dict() for alert in alerts],
            'session_score': self.policy_engine.get_session_risk_score(agent_id),
        }
    
    def _stream_alert(self, alert: AlertRecord):
        """Internal: stream alert to handlers"""
        if self.streamer:
            # Custom handler for alerts
            logger.warning(f"🔔 ALERT: {alert.rule_name} ({alert.severity.name}) - {alert.message}")
    
    def get_session_events(self, session_id: str) -> List[Dict[str, Any]]:
        """Retrieve all events for a session"""
        if not self.event_store:
            return []
        events = self.event_store.get_events_for_session(session_id)
        return [e.to_dict() for e in events]
    
    def get_session_risk_profile(self, session_id: str) -> Dict[str, Any]:
        """Get risk assessment for session"""
        if not self.policy_engine or not self.event_store:
            return {}
        
        score = self.policy_engine.get_session_risk_score(session_id)
        stats = self.event_store.get_stats()
        
        return {
            'session_id': session_id,
            'total_risk_score': score,
            'risk_level': self._score_to_level(score),
            'event_stats': stats,
            'timestamp': datetime.now().isoformat(),
        }
    
    def _score_to_level(self, score: int) -> str:
        """Convert numeric score to risk level"""
        if score == 0:
            return "NONE"
        elif score < 20:
            return "LOW"
        elif score < 50:
            return "MEDIUM"
        elif score < 100:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def get_runtime_status(self) -> Dict[str, Any]:
        """Get overall runtime health"""
        return {
            'timestamp': datetime.now().isoformat(),
            'running': self._running,
            'components': {
                'ebpf_probe': bool(self.probe_runtime),
                'event_store': bool(self.event_store),
                'policy_engine': bool(self.policy_engine),
                'streamer': bool(self.streamer),
            },
            'statistics': self.event_store.get_stats() if self.event_store else {},
        }


# ============================================================================
# Example usage / integration test
# ============================================================================

def test_runtime():
    """Integration test of full runtime pipeline"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(name)s: %(message)s"
    )
    
    logger.info("=== AgentSight Runtime Integration Test ===\n")
    
    # Create runtime
    runtime = AgentSightRuntime(
        ebpf_source="/workspaces/Test/src/ebpf/programs/probe.c",
        db_path="/tmp/agentsight_test.db",
        policy_yaml="/tmp/security_policy.yaml",  # Optional
    )
    
    # Initialize
    if not runtime.initialize():
        logger.error("Initialization failed")
        return False
    
    # Simulate some kernel events
    test_events = [
        KernelEvent(
            timestamp_ns=1000000000,
            event_type=1,  # EXEC
            pid=1234,
            ppid=1,
            uid=1000,
            gid=1000,
            comm="curl",
            data={'exec': {'filename': '/usr/bin/curl', 'argc': 2}},
        ),
        KernelEvent(
            timestamp_ns=1000001000,
            event_type=1,  # EXEC
            pid=1235,
            ppid=1234,
            uid=1000,
            gid=1000,
            comm="bash",
            data={'exec': {'filename': '/bin/bash', 'argc': 1}},
        ),
    ]
    
    logger.info("Processing simulated kernel events...\n")
    
    for i, event in enumerate(test_events):
        result = runtime.process_kernel_event(event, agent_id=f"agent_1")
        logger.info(f"Event {i+1}: {result['event_id']} - {len(result['alerts'])} alerts")
    
    # Get runtime status
    status = runtime.get_runtime_status()
    logger.info(f"\nRuntime status:\n{json.dumps(status, indent=2)}")
    
    return True


if __name__ == "__main__":
    test_runtime()
