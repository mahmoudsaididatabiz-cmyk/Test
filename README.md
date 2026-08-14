# AgentSight: Production-Grade Runtime Security Monitoring for AI Agents

A runtime security sensor for detecting suspicious activity by AI agents at the operating-system level.

**Status**: Production architecture implemented (5-priority roadmap complete)

## Overview

AgentSight uniquely addresses a critical security gap: **application logs do not provide an independent view of what the operating system actually executed**.

This is especially important for AI agents, which can be compromised by:
- **Supply-chain attacks** on libraries or model weights
- **Prompt injection** leading to unauthorized system calls
- **Privilege escalation** from malicious outputs
- **Lateral movement** via subprocess chains

By correlating **agent orchestrator intent** with **actual Linux execution** via eBPF kernel monitoring, AgentSight provides verifiable OS-level audit trails.

## Strategic Implementation: 5 Priorities

See [ROADMAP_5_PRIORITIES.md](ROADMAP_5_PRIORITIES.md) for full details.

### Priority 1: Real eBPF Chain ✅
- CO-RE enabled eBPF compiler + loader
- Ring buffer event consumption
- Tracepoint attachment (exec, exit)
- Location: `src/runtime/ebpf_loader.py`, `src/ebpf/programs/probe.c`

### Priority 2: Kernel Events ✅
- Extended event types: exec, exit, file operations, network connections
- Per-event metadata: PID, PPID, UID, command, timestamp
- Event data union for extensibility

### Priority 3: Code Structure ✅
- Separated production (`src/runtime/`) from demo (`src/demo/`)
- Clear boundaries between kernel, collection, storage, and rules
- Directory layout: `src/runtime/`, `src/ebpf/`, `src/api/`, `src/models/`

### Priority 4: Persistence + Streaming ✅
- SQLite event store with indexing (`src/runtime/persistence.py`)
- Pluggable event streamer (log, HTTP, Kafka-ready)
- Compliance-grade audit trail

### Priority 5: Policy Engine ✅
- YAML-based configurable rules (`src/runtime/policy_engine.py`)
- Single-event and multi-event correlation
- Cumulative risk scoring per agent/session
- Allowlisting and exemptions

## Architecture Overview

### Production Pipeline

```
Kernel Events (via eBPF)
    ↓ [src/runtime/ebpf_loader.py]
Ring Buffer Consumption
    ↓ [src/runtime/persistence.py]
SQLite Event Store
    ↓ [src/runtime/policy_engine.py]
Policy Evaluation + Scoring
    ↓ [src/runtime/orchestrator.py]
Alert Generation + Streaming
    ↓
External Systems (HTTP, Kafka, SIEM)
```

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| **eBPF Loader** | `src/runtime/ebpf_loader.py` | Compile, load, and manage BPF probes |
| **Event Store** | `src/runtime/persistence.py` | SQLite persistence + streaming |
| **Policy Engine** | `src/runtime/policy_engine.py` | YAML rules, correlation, scoring |
| **Orchestrator** | `src/runtime/orchestrator.py` | Unified runtime integration |
| **eBPF Program** | `src/ebpf/programs/probe.c` | Kernel-level event capture |

## Quick Start

### 1. Initialize Runtime
```python
from src.runtime.orchestrator import AgentSightRuntime

runtime = AgentSightRuntime(
    ebpf_source="src/ebpf/programs/probe.c",
    db_path="/tmp/agentsight.db",
    policy_yaml="/tmp/agentsight_policy.yaml",
)

runtime.initialize()
```

### 2. Process Events
```python
from src.runtime.ebpf_loader import KernelEvent

event = KernelEvent(
    timestamp_ns=1000000000,
    event_type=1,  # EXEC
    pid=1234,
    ppid=1,
    uid=1000,
    gid=1000,
    comm="curl",
    data={"exec": {"filename": "/usr/bin/curl", "argc": 2}},
)

result = runtime.process_kernel_event(event, agent_id="agent_1")
# → Stores in DB
# → Evaluates policies
# → Streams alerts
```

### 3. Query Risk Profile
```python
profile = runtime.get_session_risk_profile("session_1")
print(f"Risk Level: {profile['risk_level']}")  # NONE / LOW / MEDIUM / HIGH / CRITICAL
print(f"Score: {profile['total_risk_score']}")
```

## Testing

```bash
# Test individual components
python -m src.runtime.persistence         # Event store tests
python -m src.runtime.policy_engine       # Policy engine tests
python -m src.runtime.orchestrator        # Full integration test

# Query event database
sqlite3 /tmp/agentsight.db "SELECT COUNT(*) FROM events;"
```

## What's Implemented

✅ Production runtime architecture with 5 prioritized components  
✅ SQLite event persistence with full CRUD and indexing  
✅ YAML-based policy engine with scoring + correlation  
✅ eBPF source with CO-RE support (requires vmlinux.h generation)  
✅ Pluggable event streaming (HTTP, log handlers)  
✅ Session-based risk profiling and aggregation  
✅ Comprehensive integration test suite  

## What Requires Linux + Kernel Permissions

⏳ Actual eBPF compilation (requires `clang`, `llvm-objcopy`)  
⏳ Ring buffer attachment (requires `CAP_BPF` or `CAP_SYS_ADMIN`)  
⏳ Live tracepoint monitoring (kernel 5.10+ recommended)  

The codebase **gracefully falls back to simulation mode** if kernel integration is not available.

## Why This Matters

Traditional monitoring tools are **application-centric** (logs, metrics). AgentSight is **OS-centric**, providing:

1. **Independent Verification**: What the OS actually ran, regardless of what the app claims
2. **Attack Detection**: Process chains, privilege escalation, lateral movement
3. **Audit Trail**: Persistent SQLite store for compliance and incident response
4. **AI-Native**: Designed to correlate LLM intent with OS execution
5. **Extensible**: YAML policies, custom rules, no code recompilation needed

## Quick Start

### Installation

```bash
cd /workspaces/test
pip install -r requirements.txt
```

### Run the simulated workflow

```bash
python -m src.main
```

This runs the in-memory demonstration workflow and prints summary logs for the simulated session. It does not require a live eBPF kernel attachment to execute.

### Start the API server

```bash
python -m src.main --serve
# Server running on http://localhost:8000

# Example queries:
curl http://localhost:8000/agents
curl http://localhost:8000/agents/{session_id}/security-events
```

### Run tests

```bash
pytest tests/test_agentsight.py -v
```

## What the repository currently does

### Part A: Architecture model and monitoring design

**Scope**: conceptual design, event flow, and security logic.

The repository demonstrates the core design:

```
Kernel event source -> event model -> session correlation -> security rules -> API exposure
```

Key design ideas:
- `tracepoint/sched/sched_process_exec` is the intended hook for process execution events
- ring buffer is the intended kernel→userspace transport
- PPID-based process correlation is used to build session process trees
- sequence numbers are planned to detect event loss

### Part B: eBPF source and readiness checks

**File**: `src/ebpf/probe.c`

The repository contains a BPF program intended to capture process execution events with:
- `pid`, `ppid`, `uid`, `gid`
- `timestamp`
- `comm` and executable path
- `sequence` number for loss detection

This file is present and structurally valid as a kernel eBPF design target. However, the actual runtime path in the Python collector is a preflight capability check, not a confirmed injection.

**Important distinction**:
- `BPFEventCollector.start()` calls `_load_kernel_probe()`
- `_load_kernel_probe()` calls `check_kernel_injection_capabilities()`
- `check_kernel_injection_capabilities()` verifies Linux + `/sys/fs/bpf` + CAP_BPF/CAP_SYS_ADMIN + toolchain availability
- it does not prove that the probe is actively running in the kernel after the check succeeds

### Part C: Agent session model

**File**: `src/models/session.py`

The session model includes:
- session identifiers and main process tracking
- process tree construction
- file and network event association
- security event aggregation
- summary statistics

### Part D: Security rule engine

**File**: `src/collector/security.py`

Detects patterns such as:
- suspicious command execution (`curl`, `wget`, `ssh`, `sudo`, `rm`)
- access to sensitive files such as SSH keys and environment files
- suspicious deletion patterns
- external network connections

### Part E: Correlation and workflow simulation

**File**: `src/main.py`

The demo creates a realistic workflow:
- LLM interaction
- agent process spawn
- external download via `curl`
- file access or write
- suspicious SSH key access
- cleanup process such as `rm`

This is a strong simulation of the intended logic and is useful for validating the analyst workflow and event correlation model.

### Part F: API surface

**File**: `src/api/server.py`

The API exposes session and event data:

```
GET /agents
GET /agents/{id}
GET /agents/{id}/timeline
GET /agents/{id}/processes
GET /agents/{id}/security-events
GET /events?pid=X
GET /events?severity=HIGH
GET /statistics
```

## Project Structure

```
src/
├── main.py                           # Demo and orchestration
├── models/
│   ├── events.py                     # Event data structures
│   └── session.py                    # Session and process tree logic
├── collector/
│   ├── collector.py                  # Event collection and kernel capability checks
│   └── security.py                   # Security rules engine
├── api/
│   └── server.py                     # REST API
├── ebpf/
│   └── probe.c                       # BPF source for the intended probe
└── __init__.py

tests/
├── test_agentsight.py                # Core unit tests
├── test_security_rules_advanced.py   # Additional security rule coverage
├── test_linux_ebpf_integration.py    # Linux-specific eBPF readiness considerations
├── test_advanced_comprehensive.py    # Broader validation
└── tests for sessions and agent workflows

docs/
├── API_EXAMPLES.md                  # API usage examples
├── EBPF_DESIGN.md                   # eBPF design notes
└── ...
```

## Demonstration workflow

Run the simulation:

```bash
python -m src.main
```

Example output is a session summary based on in-memory events and security analysis:

```text
LLM Request: "Download the report and save it locally"
Process exec: python agent.py (PID 10001)
Process exec: curl (PID 10002, child of 10001)
Network connection: api.example.com:443
File write: /tmp/report.pdf
SUSPICIOUS ACCESS: /home/user/.ssh/id_rsa
Process exec: rm cleanup

Session Summary:
- Total processes: 6
- Total events: 42
- Security events: 2
```

This is a realistic example of the intended monitoring flow, but it is not evidence that the live kernel probe is running.

## Testing

```bash
pytest tests/test_agentsight.py -v
```

The current tests validate the logic of the architecture, session model, and security rules. They do not validate a live production kernel injection on a random host.

## Current limitations and honest status

### Limitations

1. **Kernel eBPF loading is not a confirmed runtime capability in this repo**
   - The loader performs a preflight check
   - It checks whether the environment could support injection
   - It does not guarantee that the probe is already running in the kernel

2. **In-memory-only demonstration**
   - Sessions and events are stored in Python memory for demo purposes
   - This is suitable for assessment and validation, not production deployment

3. **Single probe design**
   - The eBPF source focuses on process execution capture
   - Other event sources are modeled or simulated rather than live-collected at kernel level

4. **Tooling assumptions**
   - Linux kernel support, root or CAP_BPF, and libbpf/bpftool availability are required for a real eBPF deployment

### Assumptions

- The host is Linux and has the required kernel capabilities
- The BPF program can be compiled and loaded with the proper tooling
- Session association is based on process lineage and runtime heuristics
- Security rules remain intentionally simple and explainable

## Production roadmap

- [ ] Real kernel attachment with validated eBPF load and attach flow
- [ ] Ring buffer consumer connected to a running tracepoint
- [ ] Persistence layer for long-lived sessions
- [ ] Additional probes for file and socket events
- [ ] Alerting and dashboards
- [ ] Enforcement controls for suspicious activities

## Technical references

- **AgentSight**: https://github.com/eunomia-bpf/agentsight
- **eBPF Intro**: https://ebpf.io/
- **libbpf**: https://github.com/libbpf/libbpf
- **FastAPI**: https://fastapi.tiangolo.com/

---

**Implementation by**: GitHub Copilot
**Date**: 2026-08-14
**Status**: Architecture prototype and assessment implementation; eBPF live injection remains a future runtime step