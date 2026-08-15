"""
eBPF Runtime State Machine

Implements the state machine required by the Remediation Specification:
UNSUPPORTED → PREFLIGHT_OK → COMPILED → LOADED → ATTACHED → STREAMING
                                                  ↓ (error)
                                                DEGRADED ← ERROR

Each state is explicit and transitions are validated.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Callable
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class RuntimeState(Enum):
    """
    State machine for eBPF runtime.
    
    UNSUPPORTED: Kernel/tooling/capability not supported; fallback to simulation
    PREFLIGHT_OK: Prerequisites present; compilation authorized
    COMPILED: BPF object produced and verified
    LOADED: Program/maps loaded in kernel
    ATTACHED: Hook attached to tracepoint
    STREAMING: Polling active; events consumable
    DEGRADED: Drops, decode errors, partial probe
    ERROR: Explicit failure with root cause
    """
    UNSUPPORTED = "unsupported"
    PREFLIGHT_OK = "preflight_ok"
    COMPILED = "compiled"
    LOADED = "loaded"
    ATTACHED = "attached"
    STREAMING = "streaming"
    DEGRADED = "degraded"
    ERROR = "error"


@dataclass
class RuntimeMetrics:
    """Metrics exposed by the runtime for observability."""
    
    # Event counting
    events_received_total: int = 0
    events_decoded_total: int = 0
    decode_errors_total: int = 0
    
    # Loss tracking (distinct counters)
    kernel_drops_total: int = 0  # BPF ring buffer reserve failures
    sequence_gaps_total: int = 0  # Holes in sequence numbers
    userspace_queue_drops_total: int = 0  # Drops in Python queue
    
    # Timing
    last_event_timestamp: Optional[float] = None
    last_decode_error_timestamp: Optional[float] = None
    
    # Status
    queue_depth: int = 0
    schema_version: int = 1
    consumer_thread_alive: bool = False
    attached_programs: int = 0
    
    # Timestamps
    state_entered_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dict for API response."""
        return {
            "events_received_total": self.events_received_total,
            "events_decoded_total": self.events_decoded_total,
            "decode_errors_total": self.decode_errors_total,
            "kernel_drops_total": self.kernel_drops_total,
            "sequence_gaps_total": self.sequence_gaps_total,
            "userspace_queue_drops_total": self.userspace_queue_drops_total,
            "last_event_timestamp": self.last_event_timestamp,
            "last_decode_error_timestamp": self.last_decode_error_timestamp,
            "queue_depth": self.queue_depth,
            "schema_version": self.schema_version,
            "consumer_thread_alive": self.consumer_thread_alive,
            "attached_programs": self.attached_programs,
            "state_entered_at": self.state_entered_at.isoformat() if self.state_entered_at else None,
        }


@dataclass
class StateTransition:
    """Result of a state transition."""
    
    success: bool
    from_state: RuntimeState
    to_state: RuntimeState
    reason: str
    error: Optional[Exception] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "reason": self.reason,
            "error": str(self.error) if self.error else None,
            "timestamp": self.timestamp.isoformat(),
        }


class RuntimeStateMachine:
    """
    Manages eBPF runtime state transitions.
    
    Design principle: All states are explicit; invalid transitions are rejected.
    """
    
    # Valid state transitions
    VALID_TRANSITIONS = {
        RuntimeState.UNSUPPORTED: set(),  # Terminal state (can only fallback)
        RuntimeState.PREFLIGHT_OK: {RuntimeState.COMPILED, RuntimeState.UNSUPPORTED},
        RuntimeState.COMPILED: {RuntimeState.LOADED, RuntimeState.ERROR},
        RuntimeState.LOADED: {RuntimeState.ATTACHED, RuntimeState.ERROR},
        RuntimeState.ATTACHED: {RuntimeState.STREAMING, RuntimeState.ERROR},
        RuntimeState.STREAMING: {RuntimeState.DEGRADED, RuntimeState.ERROR, RuntimeState.ATTACHED},
        RuntimeState.DEGRADED: {RuntimeState.STREAMING, RuntimeState.ERROR, RuntimeState.ATTACHED},
        RuntimeState.ERROR: {RuntimeState.PREFLIGHT_OK, RuntimeState.UNSUPPORTED},  # Retry or give up
    }
    
    def __init__(self):
        self.current_state = RuntimeState.UNSUPPORTED
        self.metrics = RuntimeMetrics()
        self.transition_history: list = []
        self.state_handlers: Dict[RuntimeState, Callable] = {}
        self._last_transition: Optional[StateTransition] = None
    
    def register_state_handler(self, state: RuntimeState, handler: Callable):
        """Register a callback when entering a state."""
        self.state_handlers[state] = handler
    
    def can_transition(self, to_state: RuntimeState) -> bool:
        """Check if transition from current to target state is valid."""
        return to_state in self.VALID_TRANSITIONS.get(self.current_state, set())
    
    def transition(self, to_state: RuntimeState, reason: str) -> StateTransition:
        """
        Perform a state transition with validation.
        
        Args:
            to_state: Target state
            reason: Human-readable reason for transition
            
        Returns:
            StateTransition object with result
        """
        from_state = self.current_state
        
        # Validate transition
        if to_state == from_state:
            result = StateTransition(
                success=False,
                from_state=from_state,
                to_state=to_state,
                reason=f"Already in state {to_state.value}"
            )
            self._record_transition(result)
            return result
        
        if not self.can_transition(to_state):
            result = StateTransition(
                success=False,
                from_state=from_state,
                to_state=to_state,
                reason=f"Invalid transition: {from_state.value} → {to_state.value}"
            )
            self._record_transition(result)
            return result
        
        # Perform transition
        try:
            self.current_state = to_state
            self.metrics.state_entered_at = datetime.utcnow()
            
            # Call state handler if registered
            if to_state in self.state_handlers:
                try:
                    self.state_handlers[to_state]()
                except Exception as e:
                    logger.warning(f"State handler for {to_state.value} raised: {e}")
            
            result = StateTransition(
                success=True,
                from_state=from_state,
                to_state=to_state,
                reason=reason,
                timestamp=datetime.utcnow()
            )
            
            logger.info(f"✓ State transition: {from_state.value} → {to_state.value} ({reason})")
            
        except Exception as e:
            result = StateTransition(
                success=False,
                from_state=from_state,
                to_state=to_state,
                reason=f"Exception during transition: {e}",
                error=e
            )
            logger.error(f"✗ Transition failed: {result.reason}")
        
        self._record_transition(result)
        return result
    
    def _record_transition(self, transition: StateTransition):
        """Record transition in history."""
        self.transition_history.append(transition)
        self._last_transition = transition
        if len(self.transition_history) > 1000:
            self.transition_history = self.transition_history[-500:]  # Keep last 500
    
    def is_streaming(self) -> bool:
        """Check if runtime is actively streaming events."""
        return self.current_state == RuntimeState.STREAMING
    
    def is_healthy(self) -> bool:
        """Check if runtime is in a healthy state."""
        return self.current_state in (RuntimeState.STREAMING, RuntimeState.DEGRADED)
    
    def is_ready(self) -> bool:
        """Check if runtime is ready to serve requests."""
        return self.current_state == RuntimeState.STREAMING
    
    def get_status_dict(self) -> Dict[str, Any]:
        """Get complete runtime status for health endpoint."""
        return {
            "runtime_state": self.current_state.value,
            "is_healthy": self.is_healthy(),
            "is_ready": self.is_ready(),
            "is_streaming": self.is_streaming(),
            "last_transition": self._last_transition.to_dict() if self._last_transition else None,
            "metrics": self.metrics.to_dict(),
        }


# Global state machine instance
_state_machine: Optional[RuntimeStateMachine] = None


def get_state_machine() -> RuntimeStateMachine:
    """Get or create global state machine."""
    global _state_machine
    if _state_machine is None:
        _state_machine = RuntimeStateMachine()
    return _state_machine
