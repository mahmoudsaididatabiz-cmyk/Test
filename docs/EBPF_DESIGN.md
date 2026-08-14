"""
eBPF Design Choices and Scalability Analysis

This document explains the detailed design decisions made in probe.c
and how the system scales under load.
"""

# Part B: eBPF System Event Probe - Design Deep Dive

## Chosen Hook: tracepoint/sched/sched_process_exec

### Why This Hook?

```
sched_process_exec tracepoint
┌─────────────────────────────────────────┐
│ Fires AFTER successful execve()         │
│                                          │
│ At this point:                          │
│ ✓ New binary is fully loaded            │
│ ✓ Process is in scheduler               │
│ ✓ All information is complete           │
│ ✓ No race conditions                    │
└─────────────────────────────────────────┘
```

### Compared to Alternatives

#### Alternative 1: syscall/sys_enter_execve (Syscall Tracing)

```
sys_enter_execve
┌──────────────────────────────────────┐
│ Fires at syscall entry               │
│                                       │
│ Problems:                            │
│ ✗ Called BEFORE execve completes    │
│ ✗ Can capture process that fails    │
│ ✗ Arguments still in user memory    │
│ ✗ Race condition: process exits     │
│        before handler completes     │
│ ✗ Overhead: every syscall has cost  │
└──────────────────────────────────────┘
```

#### Alternative 2: syscall/sys_exit_execve (Syscall Return)

```
sys_exit_execve
┌──────────────────────────────────────┐
│ Fires at syscall return              │
│                                       │
│ Issues:                              │
│ ✗ Still captures failures (exit!=0) │
│ ✗ Process structure may be different│
│ ✗ Arguments harder to extract       │
└──────────────────────────────────────┘
```

### Chosen: sched_process_exec

```
tracepoint/sched/sched_process_exec
┌──────────────────────────────────────────────────────┐
│ ✓ Fires AFTER successful execve (only winners)      │
│ ✓ Process fully initialized in kernel               │
│ ✓ Direct access to task_struct and bprm            │
│ ✓ Provided by kernel scheduler subsystem           │
│ ✓ Low overhead: only on successful exec            │
│ ✓ Clean abstraction: no syscall grit               │
└──────────────────────────────────────────────────────┘
```

## Ring Buffer vs. Alternatives

### Selected: BPF_MAP_TYPE_RINGBUF

**Modern (Linux 5.8+)** lock-free circular buffer:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB
} events SEC(".maps");
```

**Userspace**:
```python
ring_buffer_size = 256 * 1024
consumer.consume(callback=process_event)
```

#### Comparison Matrix

| Feature | Ring Buffer | Perf Buffer | Regular Map |
|---------|------------|------------|-------------|
| **Per-CPU** | No (single) | Yes | No |
| **Lock-free** | Yes | Yes (almost) | Maybe |
| **Backpressure** | Auto (sliding) | Manual handling | Full drop |
| **Memory** | Efficient | Per-CPU overhead | Static |
| **Mode** | Modern | Deprecated | Complex |
| **Latency** | <1ms | <1ms | Variable |

### Ring Buffer Mechanics

```
Initial state:
┌─────────────────────────────────────────────┐
│ Head: 0                                     │
│ Tail: 0                                     │
│ [empty] [empty] [empty] [empty]             │
└─────────────────────────────────────────────┘

After 4 events:
┌─────────────────────────────────────────────┐
│ Head: 4 (next write position)               │
│ Tail: 0 (userspace consumer position)       │
│ [E1] [E2] [E3] [E4] → ready to read         │
└─────────────────────────────────────────────┘

After 100 more events (buffer wrap):
┌─────────────────────────────────────────────┐
│ Head: 104 (wrapped around)                  │
│ Tail: 50 (userspace fell behind)            │
│ [E99] [E100] [E101] [E55] [E56] ...         │
│  old  old     old    new   new              │
│  ↑ events E51-E98 were auto-dropped        │
│    (backpressure: sliding window)          │
└─────────────────────────────────────────────┘
```

### Backpressure Behavior

**Key Design Advantage of Ring Buffer**:

```python
# eBPF code: never blocks
event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
if (!event) {
    return 1;  # Drop event, continue
}
bpf_ringbuf_submit(event, 0);  # Never waits

# System never stalls, even under extreme load
# Drawback: may lose events (detected via sequence numbers)
```

**Compared to Perf Buffer**:

```python
# Perf buffer approach
# Per-CPU overhead, more complex locking
# Can overflow differently on multi-core systems

# Ring buffer is simpler and more efficient
```

## Event Structure Design

### Chosen Fields

```c
struct process_event {
    __u64 timestamp;      // Why: Sequence ordering, loss detection
    __u32 pid;            // Why: Process identification
    __u32 ppid;           // Why: Process tree building (crucial!)
    __u32 uid;            // Why: Permission level changes
    __u32 gid;            // Why: File system context
    __u8 comm[16];        // Why: Quick process identification
    __u8 filename[256];   // Why: Full binary path (avoid ambiguity)
    __u64 sequence;       // Why: Detect lost events
};
```

### Not Included (Why)

```c
// ✗ argv[]: can't safely copy user memory from kernel
// ✗ environ[]: same issue, also huge
// ✗ cwd: require separate system call to /proc/self/cwd
// ✗ Maps: would require separate loop to extract

// Solution: Simulation layer provides these in test/demo
```

## Sequence Numbers: Event Loss Detection

### Implementation

```c
// Global counter incremented for each event
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(value, __u64);
} event_counter SEC(".maps");

// In eBPF:
seq = bpf_map_lookup_elem(&event_counter, &zero);
if (seq) {
    __sync_fetch_and_add(seq, 1);  // Atomic increment
    event->sequence = *seq;
}
```

### Userspace Detection

```python
class BPFEventCollector:
    def __init__(self):
        self.last_sequence = 0
        self.lost_events_count = 0
    
    def process_raw_event(self, raw_event):
        sequence = raw_event.get("sequence", 0)
        
        # Detect gap
        if sequence != self.last_sequence + 1 and self.last_sequence > 0:
            lost = sequence - self.last_sequence - 1
            self.lost_events_count += lost
            logger.warning(f"Lost {lost} events")
        
        self.last_sequence = sequence
```

### When Loss Occurs

```
Ring Buffer Lifecycle:
┌─────────────────────────────────────┐
│ Empty, Normal Load                  │  No loss
├─────────────────────────────────────┤
│ 50% Full, Acceptable                │  No loss
├─────────────────────────────────────┤
│ 90% Full, High Throughput           │  No loss (yet)
├─────────────────────────────────────┤
│ 100% Full, Events Arriving Faster   │  ← Backpressure!
│ New events → auto-drop oldest       │  Events lost
│ Userspace sees sequence gap         │  Detects via seq#
├─────────────────────────────────────┤
│ Mitigation Activated:               │
│ - Kernel filtering                  │  Reduce event rate
│ - Sampling (1 in N)                 │  
│ - Consumer thread priority boost    │  Keep up with output
└─────────────────────────────────────┘
```

## Performance Under Load

### Baseline (Idle System)

```
CPU:       < 0.1% (tracepoint inactive)
Memory:    256 KB (ring buffer)
Latency:   N/A
Events:    Occasional (shell, services)
```

### Light Load (100 events/sec)

```
CPU:       ~1-2% (polling, occasional processing)
Memory:    256 KB (ring buffer)
Latency:   <1ms kernel→userspace
Loss:      0% (buffer 1-10% full)
Status:    ✅ Healthy
```

### Medium Load (1000 events/sec)

```
CPU:       ~5-10% (continuous processing)
Memory:    256 KB (ring buffer stays <50% full)
Latency:   <1ms (but jittery)
Loss:      0% (buffer 20-50% full)
Status:    ✅ OK, consider increasing to 512 KB
```

### High Load (10,000 events/sec)

```
CPU:       ~20-30% (saturating single core)
Memory:    1 MB ring buffer (increased)
Latency:   1-5ms (backlog building)
Loss:      ~1-5% (ring buffer 80%+ full)
Status:    ⚠️  OK but approaching limits
Mitigation:
  - Kernel-side filtering (reduce 10x)
  - Sampling (1 in 10 events)
  - Multi-core consumer (scale across CPUs)
```

### Extreme Load (100,000 events/sec)

```
CPU:       60-100% (single core maxed)
Memory:    4 MB ring buffer (increased)
Latency:   10-50ms (significant delay)
Loss:      ~20-50% (events dropping)
Status:    ❌ Unsustainable without changes
Required:
  - Aggressive kernel filtering (reduce 100x)
  - Event aggregation/sampling
  - Multiple collector instances
  - Distributed processing (Kafka)
```

## Scaling Strategies

### Strategy 1: Kernel-Side Filtering

```c
// Only track descendants of specific PID
#define AGENT_PID 10001

// In eBPF probe:
if (ctx->pid != AGENT_PID && ctx->ppid != AGENT_PID) {
    return 0;  // Drop immediately, don't use buffer
}

// Impact: 10-100x reduction in events
```

### Strategy 2: Event Sampling

```c
// Sample 1 in N events
#define SAMPLE_RATE 10

// In eBPF:
if (event->sequence % SAMPLE_RATE != 0) {
    return 1;  // Skip this event
}
event->sample_rate = SAMPLE_RATE;  // Mark for scaling
```

**Userspace impact**:
```python
total_events = len(collected_events) * sample_rate
```

### Strategy 3: Aggregation

```python
# Instead of individual events, aggregate:
network_summary = {
    "remote_addr:port": count,
    "api.example.com:443": 127,
    "external.com:80": 45,
}

# Storage: 2 entries vs 172 events
# Reduction: 86x
```

### Strategy 4: Consumer Thread Optimization

```python
import os
import threading

# Run collector with high priority
collector_thread = threading.Thread(
    target=collect_loop,
    daemon=False
)

# Linux only: set priority
os.nice(-10)  # Negative = higher priority

# Result: Less context switching, better cache locality
```

### Strategy 5: Distributed Collection

```
┌──────────────────┐
│ Kernel: All PIDs │
└────────┬─────────┘
         │ filtered by PID range
    ┌────┴────┬────────┐
    ▼         ▼        ▼
Collector1  Collector2 Collector3
(PIDs 1-1k) (1k-2k)   (2k-3k)
    │         │        │
    └────┬────┴────┬───┘
         ▼         ▼
    Aggregator   Database
```

### Strategy 6: Database Persistence

```python
# Current: In-memory only
session_manager.sessions: Dict[str, AgentSession]  # Lost on restart

# Production:
class PostgresSessionStore:
    def save_session(self, session: AgentSession):
        # Partition by session_id hash
        # Retention: archive events > 30 days old
        pass
```

## Error Handling

### Event Loss Scenarios

```
1. Ring Buffer Overflow
   - Cause: High throughput > consumer capacity
   - Detection: Sequence gap
   - Recovery: Increase buffer, reduce rate
   - Impact: Some events missed (but ordered)

2. Consumer Crash
   - Cause: Userspace process killed
   - Detection: No events flowing
   - Recovery: Restart consumer (lost in-flight)
   - Impact: Data loss since last checkpoint

3. Kernel Memory Pressure
   - Cause: System-wide low memory
   - Detection: Allocation failures
   - Recovery: Kernel OOM killer (may kill collector)
   - Impact: Data loss possible

4. Timestamp Skew
   - Cause: Clock adjustment, container env
   - Detection: Backwards timestamps
   - Recovery: Monotonic clock in production
   - Impact: Timeline ordering issues
```

### Mitigation Checklist

- [ ] Sequence numbers for loss detection
- [ ] Configurable ring buffer size
- [ ] Periodic checkpointing (state save)
- [ ] Graceful degradation (sample under load)
- [ ] Monitoring/alerting on event loss
- [ ] Redundant collectors (hot standby)
- [ ] Database backup strategy

## Summary: Design Decisions

| Decision | Choice | Rationale | Trade-Off |
|----------|--------|-----------|-----------|
| **Hook** | sched_process_exec | Reliable, complete info | Only successful execs |
| **Buffer** | Ring buffer | Efficient, modern | Single stream (not per-CPU) |
| **Strategy** | Backpressure drop | Never stalls system | Events lost on overflow |
| **Sequencing** | Global counter | Simple loss detection | Atomic overhead |
| **Scaling** | Kernel filtering | Reduce at source | Requires eBPF code update |
| **Failure** | Fail-open | Process continues | Lose visibility |

All choices optimize for:
1. **Reliability**: System never stalls
2. **Simplicity**: Minimal kernel code
3. **Observability**: Loss is detectable
4. **Scalability**: Can be tuned for load
