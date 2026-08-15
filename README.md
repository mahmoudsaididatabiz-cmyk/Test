# AgentSight

Runtime security monitoring for AI agents with OS-level visibility and eBPF-based event collection.

## Status

This repository contains both:
- the original runtime/security architecture
- the remediation work required by the AgentSight Copilot remediation specification

The implementation is now aligned with the actual codebase and the PDF requirements, rather than with the older prototype-only README wording.

## Objective

AgentSight addresses a fundamental gap: application logs alone cannot prove what the operating system really executed. For AI agents, this matters because malicious or unexpected behavior can hide beneath the application layer.

The design correlates:
- agent/session context
- live kernel process events
- security policy evaluation
- persistence and observability

## Repository reality

The codebase is structured around two complementary layers:

1. Legacy runtime components under src/runtime
   - ebpf_loader.py
   - persistence.py
   - policy_engine.py
   - orchestrator.py

2. Remediation components under src/collector
   - runtime_state.py
   - ring_buffer_consumer.py
   - collector.py
   - security.py / security_enhanced.py

This is not a contradictory setup: the runtime layer remains the higher-level execution and policy flow, while the collector layer implements the concrete remediation requirements from the PDF.

## Architecture overview

```text
Kernel events / tracepoints
        ↓
BPF ring buffer
        ↓
RingBufferConsumer + RingBufferDecoder
        ↓
RuntimeStateMachine (preflight → compiled → loaded → attached → streaming)
        ↓
Policy evaluation + persistence + session correlation
        ↓
Alerting / API / observability
```

## Remediation implementation aligned with the PDF

The repository now includes the main P0/P1 remediation elements required by the specification.

### P0-1: Real ring buffer consumer
- `src/collector/ring_buffer_consumer.py`
- Decodes raw binary kernel events using a strict struct schema
- Validates schema version and event type
- Handles malformed/truncated payloads safely
- Uses bounded queue backpressure and drop metrics

### P0-2: Explicit runtime state machine
- `src/collector/runtime_state.py`
- Replaces ambiguous boolean checks with explicit states:
  - UNSUPPORTED
  - PREFLIGHT_OK
  - COMPILED
  - LOADED
  - ATTACHED
  - STREAMING
  - DEGRADED
  - ERROR
- Enforces valid transitions and preserves historical state changes

### P0-3: Loss tracking and observability
- Distinct counters for:
  - kernel drops
  - sequence gaps
  - userspace queue drops
  - decode errors
- Required for production readiness and operational diagnosis

### P0-4: Kernel integration test structure
- The project includes structured kernel tests and non-privileged skip logic for CI environments
- This keeps the validation path honest while remaining runnable on constrained hosts

### P1-2: Event schema versioning
- `EVENT_SCHEMA_VERSION = 1`
- Binary payload validation rejects incompatible versions and corrupted data

## Project structure

```text
src/
├── api/
│   └── server.py
├── collector/
│   ├── collector.py
│   ├── ring_buffer_consumer.py
│   ├── runtime_state.py
│   ├── security.py
│   └── security_enhanced.py
├── ebpf/
│   └── probe.c
├── main.py
├── models/
│   ├── events.py
│   └── session.py
├── runtime/
│   ├── ebpf_loader.py
│   ├── orchestrator.py
│   ├── persistence.py
│   └── policy_engine.py
└── __init__.py

tests/
├── comprehensive_remediation_tests.py
├── test_agentsight.py
├── test_advanced_comprehensive.py
├── test_linux_ebpf_integration.py
├── test_security_rules_advanced.py
└── ...
```

## Quick start

### 1. Use the runtime state machine

```python
from src.collector.runtime_state import RuntimeState, RuntimeStateMachine

sm = RuntimeStateMachine()

sm.transition(RuntimeState.PREFLIGHT_OK, "capabilities verified")
sm.transition(RuntimeState.COMPILED, "BPF object compiled")
sm.transition(RuntimeState.LOADED, "program loaded")
sm.transition(RuntimeState.ATTACHED, "tracepoint attached")
sm.transition(RuntimeState.STREAMING, "events are flowing")

print(sm.current_state)
print(sm.get_status_dict())
```

### 2. Decode a kernel event

```python
from src.collector.ring_buffer_consumer import RingBufferDecoder

payload = b"\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
decoder = RingBufferDecoder()
success, event, reason = decoder.decode_event(payload)
print(success, reason)
```

### 3. Start the consumer

```python
from src.collector.ring_buffer_consumer import RingBufferConsumer

consumer = RingBufferConsumer(max_queue_size=256)
consumer.start()
# attach a callback or feed events into the queue in the real deployment
```

## Testing

The repository includes the structured remediation suite for the PDF requirements.

```bash
pytest tests/comprehensive_remediation_tests.py -k "not kernel" -v
```

This is the relevant validation path for the runtime-state and ring-buffer remediation work in non-privileged environments.

## Deployment notes

### Linux + kernel requirements

Real eBPF runtime collection still depends on host capabilities such as:
- Linux kernel with supported tracing features
- `CAP_BPF` or equivalent privileges
- `/sys/fs/bpf` access
- clang / llvm / bpftool tooling availability

The code is written to be production-aware, but privileged kernel execution must be validated on the target host.

## Why this repository matters

AgentSight is designed to provide verifiable OS-level evidence for agent activity.

Its key advantages are:
- independent process visibility at the kernel layer
- explicit runtime lifecycle tracking
- drop/loss monitoring for operational integrity
- structured validation for security-critical behavior
- compatibility with audit and incident response workflows

## Relevant documentation

See the following files for deeper context:
- `REMEDIATION_SUMMARY.md`
- `REMEDIATION_VALIDATION.md`
- `REMEDIATION_IMPLEMENTATION.md`
- `DELIVERABLES.md`
- `PROJECT_SUMMARY.md`

## Legacy note

The older 5-priority roadmap remains relevant as project context, but the current repository has advanced beyond the original prototype. The README now reflects the actual implementation state, including the new remediation layer and the real runtime collector components.

---

Status: aligned with the codebase and the remediation specification.
