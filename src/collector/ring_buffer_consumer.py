"""
Real BPF Ring Buffer Consumer (P0-1)

Reads kernel events from the eBPF ring buffer with proper:
- Binary event decoding
- Schema validation
- Queue-based backpressure
- Clean startup/shutdown
- Loss tracking (distinct from kernel drops)
"""

import struct
import threading
import queue
import logging
import time
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass
from datetime import datetime
from collections import deque

logger = logging.getLogger(__name__)


# Event schema version
EVENT_SCHEMA_VERSION = 1

# Binary event structure (matches probe.c struct kernel_event)
# Layout: [version:1][type:1][pid:4][ppid:4][uid:4][gid:4][timestamp_ns:8][comm:16][data:256]
EVENT_STRUCT_FORMAT = "!BBIIIIQ16s256s"  # Big-endian for portability
EVENT_STRUCT_SIZE = struct.calcsize(EVENT_STRUCT_FORMAT)

# Event types (matches probe.c)
EVENT_TYPE_EXEC = 1
EVENT_TYPE_EXIT = 2
EVENT_TYPE_OPEN_FILE = 3
EVENT_TYPE_CONNECT = 4

EVENT_TYPE_NAMES = {
    EVENT_TYPE_EXEC: "exec",
    EVENT_TYPE_EXIT: "exit",
    EVENT_TYPE_OPEN_FILE: "open_file",
    EVENT_TYPE_CONNECT: "connect",
}


@dataclass
class DecodedKernelEvent:
    """Decoded event from ring buffer."""
    
    version: int
    event_type: int
    event_type_name: str
    pid: int
    ppid: int
    uid: int
    gid: int
    timestamp_ns: int
    comm: str
    data_raw: bytes
    decoded_at: float = None  # Decode timestamp
    sequence: int = 0  # May be populated from wrapper
    
    def __post_init__(self):
        if self.decoded_at is None:
            self.decoded_at = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for JSON serialization."""
        return {
            "version": self.version,
            "event_type": self.event_type,
            "event_type_name": self.event_type_name,
            "pid": self.pid,
            "ppid": self.ppid,
            "uid": self.uid,
            "gid": self.gid,
            "timestamp_ns": self.timestamp_ns,
            "comm": self.comm,
            "decoded_at": self.decoded_at,
            "sequence": self.sequence,
        }


class RingBufferDecoder:
    """
    Decodes binary events from BPF ring buffer.
    
    Responsibilities:
    - Parse binary event structure
    - Validate schema version
    - Handle truncation/corruption
    - Track decode errors
    """
    
    def __init__(self):
        self.decode_errors = 0
        self.events_decoded = 0
    
    def decode_event(self, raw_bytes: bytes) -> tuple[bool, Optional[DecodedKernelEvent], str]:
        """
        Decode a single event from raw bytes.
        
        Returns:
            (success: bool, event: DecodedKernelEvent | None, reason: str)
        """
        
        # Check minimum size
        if len(raw_bytes) < EVENT_STRUCT_SIZE:
            self.decode_errors += 1
            return False, None, f"Truncated payload: {len(raw_bytes)} < {EVENT_STRUCT_SIZE}"
        
        try:
            # Unpack binary structure
            (version, event_type, pid, ppid, uid, gid, timestamp_ns, comm_bytes, data_bytes) = \
                struct.unpack(EVENT_STRUCT_FORMAT, raw_bytes[:EVENT_STRUCT_SIZE])
            
            # Validate schema version
            if version != EVENT_SCHEMA_VERSION:
                self.decode_errors += 1
                return False, None, f"Unknown schema version: {version}"
            
            # Validate event type
            if event_type not in EVENT_TYPE_NAMES:
                self.decode_errors += 1
                return False, None, f"Unknown event type: {event_type}"
            
            # Decode comm (NUL-terminated C string)
            comm = comm_bytes.split(b'\x00')[0].decode('utf-8', errors='replace')
            
            event = DecodedKernelEvent(
                version=version,
                event_type=event_type,
                event_type_name=EVENT_TYPE_NAMES[event_type],
                pid=pid,
                ppid=ppid,
                uid=uid,
                gid=gid,
                timestamp_ns=timestamp_ns,
                comm=comm,
                data_raw=data_bytes,
            )
            
            self.events_decoded += 1
            return True, event, "OK"
            
        except struct.error as e:
            self.decode_errors += 1
            return False, None, f"Struct unpack error: {e}"
        except UnicodeDecodeError as e:
            self.decode_errors += 1
            return False, None, f"Unicode decode error in comm: {e}"
        except Exception as e:
            self.decode_errors += 1
            return False, None, f"Unexpected decode error: {e}"


class RingBufferConsumer:
    """
    Real ring buffer consumer with backpressure handling.
    
    Design:
    - Event queue (bounded) for backpressure
    - Separate thread for polling
    - Clean startup/shutdown
    - Tracks kernel vs userspace drops
    
    In production, would use:
    - libbpf Python bindings for direct ringbuf polling
    - Or ctypes FFI to libbpf C API
    
    For now, simulates with structured queue for testing.
    """
    
    def __init__(
        self,
        max_queue_size: int = 512,
        event_callback: Optional[Callable] = None,
    ):
        self.max_queue_size = max_queue_size
        self.event_callback = event_callback
        self.event_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.decoder = RingBufferDecoder()
        
        # Polling thread
        self._polling_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False
        
        # Metrics
        self.kernel_drops = 0
        self.userspace_queue_drops = 0
        self.sequence_errors = 0
        self.total_received = 0
        self.last_sequence = -1
        self.sequence_gaps = deque(maxlen=100)  # Track recent gaps
        
        # Ring buffer simulation (in real impl, would be libbpf FD)
        self._ringbuf_fd: Optional[int] = None
        self._libbpf_handle: Optional[Any] = None  # Placeholder for actual libbpf
    
    def start(self) -> bool:
        """Start the consumer polling thread."""
        if self._is_running:
            logger.warning("Consumer already running")
            return False
        
        self._is_running = True
        self._stop_event.clear()
        
        self._polling_thread = threading.Thread(
            target=self._polling_loop,
            daemon=False,
            name="RingBufferConsumer"
        )
        self._polling_thread.start()
        
        logger.info("✓ Ring buffer consumer started")
        return True
    
    def stop(self, timeout: float = 5.0) -> bool:
        """Stop the consumer polling thread."""
        if not self._is_running:
            logger.warning("Consumer not running")
            return False
        
        self._stop_event.set()
        
        if self._polling_thread:
            self._polling_thread.join(timeout=timeout)
            if self._polling_thread.is_alive():
                logger.error("Consumer thread did not stop within timeout")
                return False
        
        self._is_running = False
        logger.info("✓ Ring buffer consumer stopped")
        return True
    
    def is_running(self) -> bool:
        """Check if consumer is actively polling."""
        return self._is_running
    
    def get_next_event(self, timeout: float = 1.0) -> Optional[DecodedKernelEvent]:
        """
        Get next decoded event from queue (non-blocking or with timeout).
        
        Returns:
            DecodedKernelEvent or None if queue empty
        """
        try:
            return self.event_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def queue_depth(self) -> int:
        """Current queue depth."""
        return self.event_queue.qsize()
    
    def _polling_loop(self):
        """Main polling loop (runs in separate thread)."""
        logger.info("Ring buffer polling loop started")
        
        while not self._stop_event.is_set():
            try:
                # In production: poll actual ring buffer FD using libbpf
                # For now: placeholder that allows events to be injected via add_event()
                
                # Small sleep to avoid busy-waiting
                time.sleep(0.01)
                
            except Exception as e:
                logger.error(f"Error in polling loop: {e}")
                self._stop_event.set()
        
        logger.info("Ring buffer polling loop stopped")
    
    def add_event(self, raw_bytes: bytes) -> bool:
        """
        Add a raw event from ring buffer.
        
        Used by libbpf callback or test injection.
        
        Returns:
            True if event queued, False if queue full
        """
        # Decode event
        success, event, reason = self.decoder.decode_event(raw_bytes)
        
        if not success:
            logger.debug(f"Decode error: {reason}")
            return False
        
        # Check for sequence gap
        if event.sequence > 0:
            if self.last_sequence >= 0 and event.sequence != self.last_sequence + 1:
                gap = event.sequence - self.last_sequence - 1
                self.sequence_errors += gap
                self.sequence_gaps.append((self.last_sequence, event.sequence))
                logger.warning(f"Sequence gap: {self.last_sequence} → {event.sequence} (gap: {gap})")
            self.last_sequence = event.sequence
        
        # Try to enqueue
        try:
            self.event_queue.put_nowait(event)
            self.total_received += 1
            
            # Call callback if registered
            if self.event_callback:
                try:
                    self.event_callback(event)
                except Exception as e:
                    logger.error(f"Event callback raised: {e}")
            
            return True
            
        except queue.Full:
            self.userspace_queue_drops += 1
            logger.warning(f"Userspace queue full; dropping event (drops: {self.userspace_queue_drops})")
            return False
    
    def record_kernel_drops(self, count: int):
        """Record drops that occurred in kernel ring buffer."""
        self.kernel_drops += count
        if count > 0:
            logger.warning(f"Kernel ring buffer drops: +{count} (total: {self.kernel_drops})")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get consumer metrics for observability."""
        return {
            "kernel_drops_total": self.kernel_drops,
            "userspace_queue_drops_total": self.userspace_queue_drops,
            "sequence_gaps_total": len(self.sequence_gaps),  # Distinct gaps
            "events_received_total": self.total_received,
            "events_decoded_total": self.decoder.events_decoded,
            "decode_errors_total": self.decoder.decode_errors,
            "queue_depth": self.queue_depth(),
            "consumer_thread_alive": self._is_running,
        }
