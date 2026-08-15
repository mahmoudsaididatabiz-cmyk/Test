# AgentSight Remediation Implementation Plan

**Date**: August 15, 2026  
**Goal**: Transform prototype into genuine end-to-end eBPF runtime  
**Reference**: AgentSight_Copilot_Remediation_Specification.pdf  

## Implementation Strategy

### Phase 1: Runtime State Machine & Architecture (P0-1, P0-2)
- [ ] Implement proper state machine: UNSUPPORTED → PREFLIGHT_OK → COMPILED → LOADED → ATTACHED → STREAMING
- [ ] Create RuntimeState enum with explicit states
- [ ] Implement health/readiness endpoints with full metrics
- [ ] Add metrics exposure: events_received_total, events_decoded_total, decode_errors_total, kernel_drops_total, sequence_gaps_total

### Phase 2: Real Ring Buffer Consumer (P0-1)
- [ ] Implement actual ring buffer reading (libbpf bindings or native bridge)
- [ ] Proper decoding of binary events from kernel
- [ ] Schema validation with version checking
- [ ] Queue-based backpressure handling
- [ ] Consumer lifecycle (start, stop, clean restart)

### Phase 3: Event Schema & Loss Tracking (P0-3, P1-2)
- [ ] Add event header with version field
- [ ] Define fixed schema with proper alignment
- [ ] Track kernel drops vs sequence gaps
- [ ] Implement PID reuse detection with start times
- [ ] Add process exit handling

### Phase 4: Process Lifecycle & Correlation (P1-3, P1-5)
- [ ] Implement sched_process_exit tracking
- [ ] Add process start time tracking
- [ ] Proper parent-child correlation
- [ ] Security context correlations (fileread → egress)
- [ ] Session-based lineage tracking

### Phase 5: Security Engine Enhancement (P1-5)
- [ ] Implement contextual multi-event rules
- [ ] Add evidence tracking for alerts
- [ ] Implement correlation windows
- [ ] Add rule IDs and metadata
- [ ] Implement allowlisting per agent

### Phase 6: API Security & Scalability (P1-6, P2-1)
- [ ] Add configurable authentication
- [ ] Implement strict input validation
- [ ] Bounded pagination enforcement
- [ ] Repository abstraction (in-memory + SQLite backend)
- [ ] Health/readiness endpoints

### Phase 7: Test Suite Implementation (Section 9+)
- [ ] **UT-01 to UT-10**: Unit tests for decoder, state, rules, API
- [ ] **KI-01 to KI-08**: Kernel integration tests (requires privileges)
- [ ] **E2E-01 to E2E-04**: End-to-end tests (kernel → API)
- [ ] **ST-01 to ST-05**: Stress tests (burst, saturation, soak)
- [ ] **FT-01 to FT-05**: Fault tests (missing privileges, invalid object, etc.)
- [ ] **SEC-01 to SEC-10**: Security scenarios with rules

### Phase 8: Repository Cleanup (P2-2)
- [ ] Remove __pycache__ from git
- [ ] Create pyproject.toml with proper structure
- [ ] Organize scripts/ and docs/ directories
- [ ] Normalize tests/ structure
- [ ] Update README with kernel-live vs simulated features

## Critical Non-Negotiables (Definition of Done)

✅ **Must achieve**:
1. `/bin/echo` real execution generates event from kernel observable via API
2. No test named "real/kernel/e2e" constructs ProcessExecutionEvent directly
3. Kernel vs userspace drops are distinguished and tested
4. Collector restart has zero BPF link/FD/thread leaks
5. PID reuse and process exit are tested
6. Critical rules have positive+negative+time window+lineage tests
7. README clearly marks kernel-live vs fallback features
8. CI has privileged kernel test job
9. All unit/component tests pass without privileges
10. Code is lint/type-check clean

## File Changes Summary

| File | Changes | Priority |
|------|---------|----------|
| `src/collector/runtime_state.py` | NEW: RuntimeState enum and transitions | P0-2 |
| `src/collector/ring_buffer_consumer.py` | NEW: Real ring buffer reading | P0-1 |
| `src/collector/collector.py` | Refactor: Use new state machine + consumer | P0-1/P0-2 |
| `src/models/events.py` | Add: Schema version, event header, metadata | P1-2 |
| `src/ebpf/probe.c` | Update: Exec + exit probes, stats map, CO-RE | P1-1, P1-3 |
| `src/runtime/persistence.py` | Existing: SQLite backend (verified) | - |
| `src/runtime/policy_engine.py` | Enhance: Correlation windows, evidence, rule IDs | P1-5 |
| `src/api/server.py` | Add: Health, ready, auth, pagination, bounds | P1-6 |
| `tests/unit/` | NEW: UT-01 to UT-10 (10 unit tests) | Phase 7 |
| `tests/kernel/` | NEW: KI-01 to KI-08 (kernel integration) | Phase 7 |
| `tests/e2e/` | NEW: E2E-01 to E2E-04 (end-to-end) | Phase 7 |
| `tests/stress/` | NEW: ST-01 to ST-05 (stress/soak) | Phase 7 |
| `tests/security/` | NEW: SEC-01 to SEC-10 (scenarios) | Phase 7 |
| `README.md` | Update: Kernel-live status, test matrix | P2-2 |
| `pyproject.toml` | NEW: Build config, dependencies, lint rules | P2-2 |
| `.github/workflows/ci.yml` | NEW/Update: Privileged test jobs | Phase 7 |

## Test Execution Commands

```bash
# Fast PR suite (no privileges)
pytest -q tests/unit tests/component

# Kernel live suite (requires sudo + Linux)
sudo -E pytest -q -m kernel tests/kernel

# End-to-end
sudo -E pytest -q -m e2e tests/e2e

# Stress (dedicated runner)
sudo -E pytest -q -m stress tests/stress

# Security rules
pytest -q -m security tests/security

# Static quality
ruff check . && ruff format --check . && mypy src
```

## Success Criteria

1. **KI-02 MUST PASS**: `/bin/echo agentsight-e2e-marker` produces event visible via API
2. **E2E-01 MUST PASS**: Real kernel action → correlation → API timeline
3. **No simulation**: All "kernel" and "e2e" tests trigger real OS actions
4. **CI protected**: Release blocked without passing privileged suite
5. **Metrics truthful**: All state and drop counters verified testable

---

**Next Step**: Begin Phase 1 implementation → Runtime State Machine
