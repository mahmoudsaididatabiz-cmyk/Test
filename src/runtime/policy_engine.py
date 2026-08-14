"""
Policy engine: configurable YAML-based rules with scoring and multi-event correlation
"""
import yaml
import re
import json
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class RuleSeverity(Enum):
    """Alert severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class RuleCondition:
    """Single condition in a rule"""
    field: str           # e.g., "event.comm", "event.event_type"
    operator: str        # "eq", "regex", "in", "gt", "contains"
    value: Any
    
    def evaluate(self, event_dict: Dict[str, Any]) -> bool:
        """Evaluate condition against event data"""
        # Navigate nested field paths
        parts = self.field.split(".")
        current = event_dict
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return False
        
        if current is None:
            return False
        
        # Apply operator
        if self.operator == "eq":
            return current == self.value
        elif self.operator == "ne":
            return current != self.value
        elif self.operator == "regex":
            return bool(re.search(self.value, str(current)))
        elif self.operator == "in":
            return current in self.value
        elif self.operator == "contains":
            return self.value in str(current)
        elif self.operator == "gt":
            return current > self.value
        elif self.operator == "lt":
            return current < self.value
        else:
            logger.warning(f"Unknown operator: {self.operator}")
            return False


@dataclass
class SecurityRule:
    """Single security policy rule"""
    name: str
    description: str
    severity: RuleSeverity
    event_type: int                     # Filter by event type
    conditions: List[RuleCondition]     # All must match (AND)
    score: int = 10                     # Risk score increment
    allowlist_agents: List[str] = field(default_factory=list)  # Agents exempt from this rule
    
    def matches_event(self, event_dict: Dict[str, Any]) -> bool:
        """Check if event matches all conditions"""
        return all(cond.evaluate(event_dict) for cond in self.conditions)
    
    def is_agent_exempt(self, agent_id: str) -> bool:
        """Check if agent is on allowlist"""
        return agent_id in self.allowlist_agents


@dataclass
class CorrelationRule:
    """Multi-event correlation rule"""
    name: str
    description: str
    severity: RuleSeverity
    event_sequence: List[Dict[str, Any]]  # Ordered events to match
    time_window_ms: int = 5000             # Max time between events
    score: int = 50                        # Higher for correlations
    
    def matches_sequence(self, events: List[Dict[str, Any]]) -> bool:
        """Check if event sequence matches correlation"""
        if len(events) < len(self.event_sequence):
            return False
        
        # Check if events match in order within time window
        for i, expected_event in enumerate(self.event_sequence):
            if i >= len(events):
                return False
            
            event = events[i]
            
            # Match event type
            if "event_type" in expected_event:
                if event.get("event_type") != expected_event["event_type"]:
                    return False
            
            # Check time delta
            if i > 0:
                time_delta = (event["timestamp_ns"] - events[i-1]["timestamp_ns"]) / 1_000_000
                if time_delta > self.time_window_ms:
                    return False
            
            # Additional conditions could be checked here
        
        return True


@dataclass
class AlertRecord:
    """Generated security alert"""
    id: Optional[int] = None
    rule_name: str = ""
    severity: RuleSeverity = RuleSeverity.LOW
    message: str = ""
    event_ids: List[int] = field(default_factory=list)
    score: int = 0
    timestamp: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule": self.rule_name,
            "severity": self.severity.name,
            "message": self.message,
            "event_ids": self.event_ids,
            "score": self.score,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class SecurityPolicyEngine:
    """
    Policy evaluation engine
    - Load rules from YAML
    - Evaluate events against rules
    - Accumulate risk scores per agent/session
    - Correlate multi-event patterns
    """
    
    def __init__(self):
        self.rules: Dict[str, SecurityRule] = {}
        self.correlation_rules: Dict[str, CorrelationRule] = {}
        self.event_cache: Dict[str, List[Dict[str, Any]]] = {}  # By session/agent
        self.session_scores: Dict[str, int] = {}               # Cumulative risk
    
    def load_yaml_config(self, yaml_path: str) -> bool:
        """Load rules from YAML file"""
        try:
            with open(yaml_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Parse basic rules
            for rule_data in config.get('rules', []):
                rule = self._parse_rule(rule_data)
                if rule:
                    self.rules[rule.name] = rule
                    logger.info(f"Loaded rule: {rule.name}")
            
            # Parse correlation rules
            for corr_data in config.get('correlations', []):
                corr = self._parse_correlation(corr_data)
                if corr:
                    self.correlation_rules[corr.name] = corr
                    logger.info(f"Loaded correlation: {corr.name}")
            
            logger.info(f"✓ Loaded {len(self.rules)} rules + {len(self.correlation_rules)} correlations")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load policy config: {e}")
            return False
    
    def _parse_rule(self, rule_data: Dict[str, Any]) -> Optional[SecurityRule]:
        """Parse YAML rule definition"""
        try:
            conditions = []
            for cond_data in rule_data.get('conditions', []):
                cond = RuleCondition(
                    field=cond_data['field'],
                    operator=cond_data.get('operator', 'eq'),
                    value=cond_data['value'],
                )
                conditions.append(cond)
            
            severity = RuleSeverity[rule_data.get('severity', 'MEDIUM')]
            
            return SecurityRule(
                name=rule_data['name'],
                description=rule_data.get('description', ''),
                severity=severity,
                event_type=rule_data.get('event_type', -1),
                conditions=conditions,
                score=rule_data.get('score', 10),
                allowlist_agents=rule_data.get('allowlist_agents', []),
            )
        except Exception as e:
            logger.error(f"Failed to parse rule: {e}")
            return None
    
    def _parse_correlation(self, corr_data: Dict[str, Any]) -> Optional[CorrelationRule]:
        """Parse YAML correlation rule"""
        try:
            severity = RuleSeverity[corr_data.get('severity', 'HIGH')]
            
            return CorrelationRule(
                name=corr_data['name'],
                description=corr_data.get('description', ''),
                severity=severity,
                event_sequence=corr_data.get('event_sequence', []),
                time_window_ms=corr_data.get('time_window_ms', 5000),
                score=corr_data.get('score', 50),
            )
        except Exception as e:
            logger.error(f"Failed to parse correlation: {e}")
            return None
    
    def evaluate_event(self, event_dict: Dict[str, Any], agent_id: str = "") -> List[AlertRecord]:
        """
        Evaluate single event against all rules
        Returns list of alerts generated
        """
        alerts = []
        
        for rule_name, rule in self.rules.items():
            # Skip if event type doesn't match
            if rule.event_type != -1 and event_dict.get("event_type") != rule.event_type:
                continue
            
            # Skip if agent is exempt
            if agent_id and rule.is_agent_exempt(agent_id):
                continue
            
            # Check conditions
            if rule.matches_event(event_dict):
                alert = AlertRecord(
                    rule_name=rule_name,
                    severity=rule.severity,
                    message=f"Rule '{rule_name}': {rule.description}",
                    score=rule.score,
                    timestamp=datetime.now(),
                )
                alerts.append(alert)
                
                # Update session score
                session_id = event_dict.get("session_id", "unknown")
                self.session_scores[session_id] = self.session_scores.get(session_id, 0) + rule.score
        
        return alerts
    
    def correlate_events(self, events: List[Dict[str, Any]]) -> List[AlertRecord]:
        """
        Check event sequence against correlation rules
        """
        alerts = []
        
        for corr_name, corr_rule in self.correlation_rules.items():
            if corr_rule.matches_sequence(events):
                alert = AlertRecord(
                    rule_name=corr_name,
                    severity=corr_rule.severity,
                    message=f"Correlation '{corr_name}': {corr_rule.description}",
                    event_ids=[e.get("id") for e in events],
                    score=corr_rule.score,
                    timestamp=datetime.now(),
                )
                alerts.append(alert)
        
        return alerts
    
    def get_session_risk_score(self, session_id: str) -> int:
        """Get cumulative risk score for session"""
        return self.session_scores.get(session_id, 0)


# ============================================================================
# Example policy configuration (YAML)
# ============================================================================

EXAMPLE_POLICY_YAML = """
rules:
  - name: "Suspicious Command Execution"
    description: "Execution of known suspicious command"
    severity: HIGH
    event_type: 1  # EXEC
    score: 25
    conditions:
      - field: "comm"
        operator: "regex"
        value: "(curl|wget|nc|netcat|bash -c)"
    allowlist_agents: []

  - name: "Privilege Escalation Attempt"
    description: "Non-root user attempting sudo"
    severity: CRITICAL
    event_type: 1  # EXEC
    score: 50
    conditions:
      - field: "comm"
        operator: "eq"
        value: "sudo"
      - field: "uid"
        operator: "gt"
        value: 0

  - name: "Access to Sensitive Files"
    description: "Opening /etc/shadow or /etc/passwd"
    severity: HIGH
    event_type: 3  # OPEN_FILE
    score: 20
    conditions:
      - field: "data.path"
        operator: "regex"
        value: "(/etc/(passwd|shadow|sudoers)|/root/.ssh)"

correlations:
  - name: "Process Chain: curl → bash"
    description: "Downloaded script immediately executed"
    severity: CRITICAL
    score: 100
    time_window_ms: 1000
    event_sequence:
      - event_type: 3  # OPEN (network resource)
      - event_type: 1  # EXEC (bash)

  - name: "Lateral Movement Pattern"
    description: "SSH connection followed by process spawn"
    severity: HIGH
    score: 75
    time_window_ms: 5000
    event_sequence:
      - event_type: 4  # CONNECT (port 22)
      - event_type: 1  # EXEC (shell)
"""


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Save example policy
    example_path = "/tmp/security_policy.yaml"
    with open(example_path, 'w') as f:
        f.write(EXAMPLE_POLICY_YAML)
    
    # Create engine and load
    engine = SecurityPolicyEngine()
    engine.load_yaml_config(example_path)
    
    # Test event
    test_event = {
        "event_type": 1,
        "comm": "curl",
        "uid": 1000,
        "pid": 1234,
        "timestamp_ns": 1000000000,
        "session_id": "session_1",
    }
    
    alerts = engine.evaluate_event(test_event)
    for alert in alerts:
        logger.info(f"Alert: {alert.to_dict()}")
