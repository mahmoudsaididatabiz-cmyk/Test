"""
Part F: Backend API

Minimal REST API for inspecting agent sessions and security events.

Endpoints:
- GET /agents                    List all agents/sessions
- GET /agents/{id}              Get session details
- GET /agents/{id}/timeline     Get events timeline
- GET /agents/{id}/processes    Get process tree
- GET /agents/{id}/security-events  Get security events
- GET /events?pid=X             Get events by PID
- GET /events?severity=HIGH     Get events by severity
- GET /health                   Health check
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
import logging

from src.models import (
    AgentSession,
    SecurityEvent,
    EventSeverity,
)
from src.collector.collector import SessionManager

logger = logging.getLogger(__name__)


class AgentSightAPI:
    """REST API server for AgentSight monitoring system."""
    
    def __init__(self, session_manager: SessionManager):
        """
        Initialize API with a session manager.
        
        Args:
            session_manager: SessionManager instance managing active sessions
        """
        self.session_manager = session_manager
        self.app = FastAPI(
            title="AgentSight API",
            description="OS-level security monitoring for AI agents",
            version="1.0.0",
        )
        self._setup_routes()
    
    def _setup_routes(self) -> None:
        """Register API routes."""
        
        @self.app.get("/health")
        async def health():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        
        # ===================================================================
        # Agents / Sessions Endpoints
        # ===================================================================
        
        @self.app.get("/agents")
        async def list_agents():
            """
            List all agent sessions.
            
            Returns:
                List of sessions with summary information
            """
            sessions = []
            for session_id, session in self.session_manager.sessions.items():
                summary = session.get_summary()
                sessions.append({
                    "session_id": session_id,
                    "agent_name": session.agent_name,
                    "main_pid": session.main_pid,
                    "start_time": session.start_time.isoformat(),
                    "end_time": session.end_time.isoformat() if session.end_time else None,
                    "is_active": session.is_active(),
                    "summary": {
                        "total_processes": summary.total_processes,
                        "total_events": summary.total_events,
                        "total_security_events": summary.total_security_events,
                        "unique_files_accessed": summary.unique_files_accessed,
                    }
                })
            return {"agents": sessions}
        
        @self.app.get("/agents/{session_id}")
        async def get_agent(session_id: str):
            """
            Get detailed information about a specific agent session.
            
            Args:
                session_id: Session identifier
            
            Returns:
                Complete session details
            """
            session = self.session_manager.get_session(session_id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
            
            summary = session.get_summary()
            return {
                "session_id": session.session_id,
                "agent_name": session.agent_name,
                "main_pid": session.main_pid,
                "main_executable": session.main_executable,
                "main_command": session.main_command,
                "start_time": session.start_time.isoformat(),
                "end_time": session.end_time.isoformat() if session.end_time else None,
                "is_active": session.is_active(),
                "summary": summary.model_dump(),
                "process_count": len(session.processes),
                "security_events_count": len(session.security_events),
            }
        
        # ===================================================================
        # Process Tree Endpoint
        # ===================================================================
        
        @self.app.get("/agents/{session_id}/processes")
        async def get_processes(session_id: str):
            """
            Get the process tree for a session.
            
            Shows parent-child relationships of all processes
            spawned by the agent.
            
            Args:
                session_id: Session identifier
            
            Returns:
                Hierarchical process tree
            """
            session = self.session_manager.get_session(session_id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
            
            return {
                "session_id": session_id,
                "process_tree": session.get_process_tree(),
                "total_processes": len(session.processes),
            }
        
        # ===================================================================
        # Timeline Endpoint
        # ===================================================================
        
        @self.app.get("/agents/{session_id}/timeline")
        async def get_timeline(
            session_id: str,
            limit: int = Query(100, ge=1, le=1000),
            offset: int = Query(0, ge=0),
        ):
            """
            Get the event timeline for a session.
            
            Returns all OS-level events in chronological order.
            
            Args:
                session_id: Session identifier
                limit: Maximum events to return (default 100)
                offset: Number of events to skip (for pagination)
            
            Returns:
                List of events with timestamps
            """
            session = self.session_manager.get_session(session_id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
            
            events = session.timeline.events
            total = len(events)
            
            # Paginate
            paginated_events = events[offset:offset + limit]
            
            return {
                "session_id": session_id,
                "total_events": total,
                "offset": offset,
                "limit": limit,
                "events": paginated_events,
            }
        
        # ===================================================================
        # Security Events Endpoint
        # ===================================================================
        
        @self.app.get("/agents/{session_id}/security-events")
        async def get_security_events(
            session_id: str,
            severity: Optional[str] = Query(None),
        ):
            """
            Get security events detected in a session.
            
            Args:
                session_id: Session identifier
                severity: Optional filter (LOW, MEDIUM, HIGH, CRITICAL)
            
            Returns:
                List of security events
            """
            session = self.session_manager.get_session(session_id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
            
            events = session.security_events
            
            # Filter by severity if specified
            if severity:
                try:
                    sev = EventSeverity(severity.upper())
                    events = [e for e in events if e.severity == sev]
                except ValueError:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid severity: {severity}"
                    )
            
            return {
                "session_id": session_id,
                "total_security_events": len(events),
                "events": [e.model_dump() for e in events],
            }
        
        # ===================================================================
        # Global Event Search Endpoints
        # ===================================================================
        
        @self.app.get("/events")
        async def search_events(
            pid: Optional[int] = Query(None),
            severity: Optional[str] = Query(None),
            limit: int = Query(100, ge=1, le=1000),
        ):
            """
            Search events across all sessions.
            
            Args:
                pid: Filter by process ID
                severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
                limit: Maximum results to return
            
            Returns:
                List of matching events
            """
            all_events = []
            
            # Collect security events from all sessions
            for session in self.session_manager.sessions.values():
                for event in session.security_events:
                    # Apply filters
                    if pid and event.pid != pid:
                        continue
                    if severity:
                        try:
                            sev = EventSeverity(severity.upper())
                            if event.severity != sev:
                                continue
                        except ValueError:
                            raise HTTPException(
                                status_code=400,
                                detail=f"Invalid severity: {severity}"
                            )
                    
                    all_events.append({
                        "session_id": event.session_id,
                        **event.model_dump()
                    })
            
            # Sort by timestamp and limit
            all_events.sort(key=lambda e: e["timestamp"], reverse=True)
            limited_events = all_events[:limit]
            
            return {
                "total_matches": len(all_events),
                "returned": len(limited_events),
                "limit": limit,
                "events": limited_events,
            }
        
        @self.app.get("/statistics")
        async def get_statistics():
            """
            Get overall statistics about monitored sessions.
            
            Returns:
                Aggregated metrics
            """
            total_sessions = len(self.session_manager.sessions)
            active_sessions = len(self.session_manager.get_active_sessions())
            
            total_events = 0
            total_security_events = 0
            total_processes = 0
            
            for session in self.session_manager.sessions.values():
                summary = session.get_summary()
                total_events += summary.total_events
                total_security_events += summary.total_security_events
                total_processes += summary.total_processes
            
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_sessions": total_sessions,
                "active_sessions": active_sessions,
                "total_processes": total_processes,
                "total_os_events": total_events,
                "total_security_events": total_security_events,
            }


def create_api(session_manager: SessionManager) -> FastAPI:
    """
    Factory function to create and configure the FastAPI application.
    
    Args:
        session_manager: SessionManager instance
    
    Returns:
        Configured FastAPI application
    """
    api = AgentSightAPI(session_manager)
    return api.app
