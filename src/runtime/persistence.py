"""
Persistence layer with streaming support
Stores kernel events in SQLite + optionally streams to external systems
"""
import sqlite3
import json
import threading
from pathlib import Path
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import List, Optional, Dict, Any, Callable
import logging

logger = logging.getLogger(__name__)


@dataclass
class PersistedEvent:
    """Event record in persistence store"""
    id: Optional[int] = None
    timestamp_ns: int = 0
    event_type: int = 0
    pid: int = 0
    ppid: int = 0
    uid: int = 0
    gid: int = 0
    comm: str = ""
    data_json: str = "{}"
    processed: bool = False
    rule_violations: str = "[]"
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Parse JSON fields back to objects for return
        try:
            d['data'] = json.loads(self.data_json)
            d['violations'] = json.loads(self.rule_violations)
        except:
            d['data'] = {}
            d['violations'] = []
        return d


class EventStore:
    """SQLite-based event persistence"""
    
    def __init__(self, db_path: str = "/tmp/agentsight_events.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        self._lock = threading.RLock()
    
    def _init_schema(self):
        """Create tables if they don't exist"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_ns INTEGER NOT NULL,
                    event_type INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    ppid INTEGER NOT NULL,
                    uid INTEGER NOT NULL,
                    gid INTEGER NOT NULL,
                    comm TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    processed BOOLEAN DEFAULT 0,
                    rule_violations TEXT DEFAULT '[]',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    agent_id TEXT NOT NULL,
                    root_pid INTEGER NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ended_at DATETIME
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT,
                    message TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (event_id) REFERENCES events(id)
                )
            """)
            
            # Create indices for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp_ns)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pid ON events(pid)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_processed ON events(processed)")
            
            conn.commit()
            logger.info(f"✓ Event store initialized: {self.db_path}")
    
    def store_event(self, event: PersistedEvent) -> int:
        """Store a single event, return ID"""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    INSERT INTO events (
                        timestamp_ns, event_type, pid, ppid, uid, gid, 
                        comm, data_json, processed, rule_violations
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.timestamp_ns,
                    event.event_type,
                    event.pid,
                    event.ppid,
                    event.uid,
                    event.gid,
                    event.comm,
                    event.data_json,
                    event.processed,
                    event.rule_violations,
                ))
                conn.commit()
                return cursor.lastrowid
    
    def store_events_batch(self, events: List[PersistedEvent]) -> List[int]:
        """Store multiple events efficiently"""
        ids = []
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                for event in events:
                    cursor = conn.execute("""
                        INSERT INTO events (
                            timestamp_ns, event_type, pid, ppid, uid, gid, 
                            comm, data_json, processed, rule_violations
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.timestamp_ns, event.event_type, event.pid, event.ppid,
                        event.uid, event.gid, event.comm, event.data_json,
                        event.processed, event.rule_violations,
                    ))
                    ids.append(cursor.lastrowid)
                conn.commit()
        
        logger.info(f"Stored {len(ids)} events in batch")
        return ids
    
    def get_unprocessed_events(self, limit: int = 100) -> List[PersistedEvent]:
        """Fetch events not yet processed by security engine"""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("""
                    SELECT * FROM events WHERE processed = 0
                    ORDER BY timestamp_ns ASC
                    LIMIT ?
                """, (limit,)).fetchall()
                
                return [self._row_to_event(row) for row in rows]
    
    def mark_processed(self, event_id: int, violations: List[str] = None):
        """Mark event as processed and optionally attach violations"""
        violations_json = json.dumps(violations or [])
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE events SET processed = 1, rule_violations = ?
                    WHERE id = ?
                """, (violations_json, event_id))
                conn.commit()
    
    def get_events_for_session(self, session_id: str) -> List[PersistedEvent]:
        """Retrieve all events for a session"""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("""
                    SELECT e.* FROM events e
                    JOIN sessions s ON e.pid IN (
                        SELECT pid FROM events WHERE comm = s.agent_id
                    )
                    WHERE s.session_id = ?
                    ORDER BY e.timestamp_ns
                """, (session_id,)).fetchall()
                
                return [self._row_to_event(row) for row in rows]
    
    def query_events(self, filters: Dict[str, Any], limit: int = 1000) -> List[PersistedEvent]:
        """
        Query events with filters
        filters: {event_type, pid, uid, processed, since_ns, until_ns}
        """
        where_clauses = []
        params = []
        
        if "event_type" in filters:
            where_clauses.append("event_type = ?")
            params.append(filters["event_type"])
        
        if "pid" in filters:
            where_clauses.append("pid = ?")
            params.append(filters["pid"])
        
        if "uid" in filters:
            where_clauses.append("uid = ?")
            params.append(filters["uid"])
        
        if "processed" in filters:
            where_clauses.append("processed = ?")
            params.append(1 if filters["processed"] else 0)
        
        if "since_ns" in filters:
            where_clauses.append("timestamp_ns >= ?")
            params.append(filters["since_ns"])
        
        if "until_ns" in filters:
            where_clauses.append("timestamp_ns <= ?")
            params.append(filters["until_ns"])
        
        query = "SELECT * FROM events"
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        query += " ORDER BY timestamp_ns DESC LIMIT ?"
        params.append(limit)
        
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(query, params).fetchall()
                return [self._row_to_event(row) for row in rows]
    
    def _row_to_event(self, row: sqlite3.Row) -> PersistedEvent:
        """Convert database row to PersistedEvent"""
        return PersistedEvent(
            id=row["id"],
            timestamp_ns=row["timestamp_ns"],
            event_type=row["event_type"],
            pid=row["pid"],
            ppid=row["ppid"],
            uid=row["uid"],
            gid=row["gid"],
            comm=row["comm"],
            data_json=row["data_json"],
            processed=row["processed"],
            rule_violations=row["rule_violations"],
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get event store statistics"""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                stats = {}
                
                # Total events
                total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                stats['total_events'] = total
                
                # Unprocessed
                unproc = conn.execute("SELECT COUNT(*) FROM events WHERE processed=0").fetchone()[0]
                stats['unprocessed'] = unproc
                
                # By type
                by_type = conn.execute("""
                    SELECT event_type, COUNT(*) as count FROM events
                    GROUP BY event_type
                """).fetchall()
                stats['by_type'] = {row[0]: row[1] for row in by_type}
                
                # With violations
                with_viol = conn.execute("""
                    SELECT COUNT(*) FROM events WHERE rule_violations != '[]'
                """).fetchone()[0]
                stats['with_violations'] = with_viol
                
                return stats


class EventStreamer:
    """Streams events to external backends (Redis, Kafka, HTTP, etc.)"""
    
    def __init__(self):
        self.handlers: List[Callable] = []
        self._running = False
    
    def register_handler(self, handler: Callable[[PersistedEvent], None]):
        """Register a handler for events"""
        self.handlers.append(handler)
        logger.info(f"Registered stream handler: {handler.__name__}")
    
    def stream_event(self, event: PersistedEvent):
        """Send event to all registered handlers"""
        for handler in self.handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Stream handler error: {e}")


# ============================================================================
# Example handlers
# ============================================================================

def log_handler(event: PersistedEvent):
    """Log events to console"""
    logger.info(f"[{event.event_type}] pid={event.pid} {event.comm}")


def http_handler(event: PersistedEvent, endpoint: str = "http://localhost:8000/events"):
    """Send to HTTP endpoint (example)"""
    import requests
    try:
        requests.post(endpoint, json=event.to_dict(), timeout=2)
    except Exception as e:
        logger.debug(f"HTTP stream failed: {e}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create store and streamer
    store = EventStore()
    streamer = EventStreamer()
    
    # Register handlers
    streamer.register_handler(log_handler)
    
    # Test: store some events
    test_events = [
        PersistedEvent(
            timestamp_ns=1000000000 + i * 1000,
            event_type=1,
            pid=1234 + i,
            ppid=1,
            uid=1000,
            gid=1000,
            comm=f"test_{i}",
            data_json='{"test": "data"}',
        )
        for i in range(5)
    ]
    
    ids = store.store_events_batch(test_events)
    logger.info(f"Stored event IDs: {ids}")
    
    # Query back
    events = store.get_unprocessed_events()
    logger.info(f"Retrieved {len(events)} unprocessed events")
    
    # Get stats
    stats = store.get_stats()
    logger.info(f"Store stats: {stats}")
