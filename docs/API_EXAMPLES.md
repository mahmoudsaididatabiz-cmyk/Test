# AgentSight REST API - Examples

Complete examples of how to use the AgentSight REST API to query agent sessions and security events.

## Quick Start

### 1. Start the API Server

```bash
python -m src.main --serve
```

Server runs on `http://localhost:8000`

### 2. Run Simulation (In Another Terminal)

```bash
python -m src.main
```

This populates the system with example data.

### 3. Query the API

```bash
curl http://localhost:8000/agents
```

## API Endpoints

### Health Check

**Request**:
```bash
curl http://localhost:8000/health
```

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2026-08-14T19:30:00.123456Z"
}
```

---

### List All Agents/Sessions

**Request**:
```bash
curl http://localhost:8000/agents
```

**Response**:
```json
{
  "agents": [
    {
      "session_id": "demo-session-1786735609",
      "agent_name": "security-agent",
      "main_pid": 10001,
      "start_time": "2026-08-14T19:26:49.550000Z",
      "is_active": false,
      "summary": {
        "total_processes": 3,
        "total_events": 7,
        "total_security_events": 3
      }
    }
  ]
}
```

---

### Get Session Details

**Request**:
```bash
curl http://localhost:8000/agents/demo-session-1786735609
```

**Response**:
```json
{
  "session_id": "demo-session-1786735609",
  "agent_name": "security-agent",
  "main_pid": 10001,
  "summary": {
    "total_processes": 3,
    "total_events": 7,
    "total_security_events": 3
  }
}
```

---

### Get Process Tree

**Request**:
```bash
curl http://localhost:8000/agents/demo-session-1786735609/processes
```

**Shows hierarchical process relationships**

---

### Get Security Events

**Request**:
```bash
curl "http://localhost:8000/agents/demo-session-1786735609/security-events?severity=HIGH"
```

**Response**:
```json
{
  "session_id": "demo-session-1786735609",
  "total_security_events": 2,
  "events": [
    {
      "severity": "HIGH",
      "rule_name": "SENSITIVE_FILE_ACCESS",
      "target": "/home/user/.ssh/id_rsa"
    },
    {
      "severity": "HIGH",
      "rule_name": "SENSITIVE_COMMAND_EXECUTION",
      "target": "/bin/rm"
    }
  ]
}
```

---

### Search Events Across Sessions

**By Severity**:
```bash
curl "http://localhost:8000/events?severity=HIGH"
```

**By PID**:
```bash
curl "http://localhost:8000/events?pid=10002"
```

---

### Get Statistics

```bash
curl http://localhost:8000/statistics
```

Returns aggregated metrics across all sessions.
