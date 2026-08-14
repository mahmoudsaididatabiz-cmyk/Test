# AgentSight: OS-Level Security Monitoring for AI Agents

An architecture-focused security monitoring prototype for detecting suspicious activity by AI agents at the operating-system level.

**Status**: Technical assessment / design prototype

## Overview

AgentSight addresses a real security gap: **application logs do not provide an independent view of what the operating system actually executed**.

This repository implements a Python-based model of that architecture: event models, session correlation, security detection rules, and a FastAPI interface. It also includes an eBPF C source file and a capability preflight loader, but it does not currently provide a verified end-to-end live kernel injection in this environment.

## Current Reality of the Implementation

The codebase is best described as a practical prototype and architecture demonstration, not a fully deployed live eBPF monitoring system.

What is implemented:
- Agent session models and process tree logic
- Event classes for process, file, network, and LLM interactions
- Security rule engine for suspicious commands, sensitive file access, and network activity
- REST API layer for session and event inspection
- Simulation of realistic workflow scenarios
- eBPF source and Linux capability checks for future kernel attachment

What is not currently guaranteed in this repo:
- a validated live eBPF program loaded into the running kernel
- a confirmed ring-buffer consumer attached to a real tracepoint in CI or on arbitrary hosts
- a production deployment with a fully verified live collector from kernel to userspace to API

The critical point is this: the project includes a preflight check for eBPF capability, but not a confirmed runtime injection. In other words, the code checks whether the environment is capable of loading a BPF program; it does not claim to have successfully injected and attached the probe in all cases.

## Architecture Overview

### High-Level Pipeline

```
Linux host capability check
    ↓
BPF source design (`src/ebpf/probe.c`)
    ↓
Capability preflight / loader readiness
    ↓
Python collector and session correlation
    ↓
Security rules engine
    ↓
API and simulation output
```

This is intentionally more conservative than the original marketing version: the runtime path is designed to fail safely when the host is not Linux, lacks permissions, lacks tooling, or is otherwise not suitable for kernel injection.

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