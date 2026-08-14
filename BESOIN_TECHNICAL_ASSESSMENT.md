# Technical assessment: AgentSight eBPF prototype

## Scope

This document describes the current project status, not a claim of full production deployment. The repository implements a credible technical prototype for OS-level monitoring of AI agent activity, with validated code paths and tests, but without a confirmed live eBPF kernel injection in every runtime environment.

## What the project demonstrates

- Process execution event modeling
- Session correlation using PID/PPID logic
- Security detection rules for suspicious actions
- FastAPI-based inspection API
- Simulation of realistic malicious or risky workflows
- Linux capability preflight checks for eBPF readiness

## Current status

The repository is a design prototype and validation artifact. It is not a guarantee of a fully running kernel monitor on arbitrary hosts. The honest and verified status is:

- architecture is implemented and testable
- the codebase is structured and modular
- security rules are implemented and exercised
- eBPF runtime is represented via source and preflight checks
- live kernel attachment remains a future deployment step

## Key technical sections

### A. Architecture and pipeline

The project models a Linux event pipeline from kernel to user space, including session correlation and security analysis.

### B. eBPF source design

The probe in [src/ebpf/probe.c](src/ebpf/probe.c) targets `sched_process_exec` and uses a ring-buffer concept for kernel-to-user-space data flow. The design is valid as a prototype and design artifact, but the runtime path is deliberately conservative.

### C. Session model

The session layer in [src/models/session.py](src/models/session.py) tracks agent execution, process ancestry, file access, network events, and security findings.

### D. Security engine

The engine in [src/collector/security.py](src/collector/security.py) analyzes suspicious commands and sensitive file access patterns.

### E. Workflow simulation

The demo in [src/main.py](src/main.py) simulates a realistic unsafe agent workflow and shows how the system would report threats.

### F. REST API

The API in [src/api/server.py](src/api/server.py) exposes sessions, timelines, process trees, and security events.

## Verification in this workspace

```bash
cd /workspaces/Test
python -m pytest -q
```

Observed result:

```text
141 passed in 26.92s
```

## Conclusion

This is a credible technical prototype and a valid assessment package. It is suitable for design review, architecture discussion, and validation of logic, but it should not be described as a confirmed live eBPF deployment without a privileged Linux host and explicit runtime validation.

#### Besoin
Corréler les prompts/réponses LLM avec les activités OS observées, permettant:
- Vérifier l'alignement entre intention (LLM) et comportement réel (OS)
- Détecter les injections de prompts
- Analyser les écarts de comportement

#### Architecture de Corrélation
```
LLMInteractionEvent (T=0ms)
├── model: "GPT-4"
├── prompt: "Process customer data safely"
└── response: "I will..."

          ↓ Time Window: 60 secondes

ProcessExecutionEvent (T=500ms)
├── argv: ["python3", "process.py"]
└── ppid: 1234

FileAccessEvent (T=600ms)
├── path: "/data/customer.csv"
└── flags: "O_RDONLY"

NetworkConnectionEvent (T=700ms)
├── remote_addr: "185.220.101.45"  ← EXTERNAL!
└── remote_port: 443

SecurityEvent (T=700ms)
├── severity: "MEDIUM"
└── rule: "EXTERNAL_NETWORK_CONNECTION"

[Continue timeline...]
```

#### Algorithme de Corrélation
```python
def correlate_llm_to_os(session):
    for llm_event in session.llm_interactions:
        llm_time = llm_event.timestamp
        
        # Fenêtre temporelle: LLM → OS events (60 sec)
        window_end = llm_time + timedelta(seconds=60)
        related_events = [e for e in session.events 
                        if llm_time < e.timestamp <= window_end]
        
        # Analyser pattern
        processes = count([e for e in related_events 
                          if e.type == PROCESS_EXECUTION])
        files = extract_paths([e for e in related_events 
                              if e.type == FILE_ACCESS])
        networks = extract_ips([e for e in related_events 
                               if e.type == NETWORK])
        violations = count([e for e in related_events 
                           if e.type == SECURITY_EVENT])
        
        # Score de risque
        risk_level = calculate_risk_score(violations)
        # CRITIQUE si: violations.count > 0 ET violations.severity >= HIGH
        
        return Correlation(
            llm_prompt=llm_event.prompt,
            os_activity={
                "processes_spawned": processes,
                "files_accessed": files,
                "networks_contacted": networks,
                "violations": violations
            },
            risk_level=risk_level
        )
```

#### Critères de Succès
- ✅ Timeline chronologique (ordered by timestamp)
- ✅ Time-windowed correlation (LLM → OS within 60s)
- ✅ Process lineage tracking (PPID relationships)
- ✅ Behavioral intent vs. reality comparison
- ✅ Automated risk scoring

---

### ✅ **PARTIE F: REST API Endpoints & Data Access**

#### Besoin
Fournir des endpoints REST pour querying:
- Sessions actives
- Détails de sessions
- Timelines d'événements
- Arbres de processus
- Résultats de sécurité

#### 9 Endpoints Requis

| # | Endpoint | Méthode | Description | Réponse |
|---|----------|---------|-------------|---------|
| 1 | `/health` | GET | Health check | `{status: "ok"}` |
| 2 | `/agents` | GET | List all sessions | `[{session_id, agent_name, start_time}]` |
| 3 | `/agents/{id}` | GET | Session details | Session complete object |
| 4 | `/agents/{id}/timeline` | GET | Event timeline (paginated) | `[events]` avec limit/offset |
| 5 | `/agents/{id}/processes` | GET | Process tree | Tree hierarchy |
| 6 | `/agents/{id}/security-events` | GET | Security violations | `[violation_events]` |
| 7 | `/events?pid=X` | GET | Search by PID | Events matching pid |
| 8 | `/events?severity=LEVEL` | GET | Filter by severity | Events with LEVEL in [LOW,MEDIUM,HIGH,CRITICAL] |
| 9 | `/statistics` | GET | Aggregate stats | `{total_sessions, total_events, violations_count}` |

#### Spécifications de Réponse
```json
GET /agents/session-001/security-events

{
  "session_id": "session-001",
  "security_events": [
    {
      "timestamp": "2026-08-14T10:30:00Z",
      "severity": "CRITICAL",
      "rule_name": "SENSITIVE_FILE_WRITE",
      "description": "Write to /etc/sudoers detected",
      "target": "/etc/sudoers",
      "pid": 5012,
      "executable": "/usr/bin/python3"
    },
    {
      "timestamp": "2026-08-14T10:30:05Z",
      "severity": "HIGH",
      "rule_name": "SENSITIVE_FILE_ACCESS",
      "target": "/home/user/.ssh/id_rsa",
      "pid": 5012
    }
  ]
}
```

#### Critères de Succès
- ✅ 9 endpoints implémentés
- ✅ Pagination support (?limit=100&offset=0)
- ✅ Severity filtering (?severity=CRITICAL,HIGH)
- ✅ Time-range queries (?from=...&to=...)
- ✅ Full-text search sur descriptions
- ✅ Efficient JSON serialization (Pydantic)

---

## 📊 RÉSUMÉ DE COUVERTURE

### Événements OS Supportés (8 types)
1. **ProcessExecutionEvent** - Exécution de processus (execve)
2. **FileAccessEvent** - Accès fichier (open, read)
3. **FileWriteEvent** - Écriture fichier
4. **FileDeleteEvent** - Suppression fichier
5. **NetworkConnectionEvent** - Connexions réseau
6. **SecurityEvent** - Violations de sécurité
7. **LLMInteractionEvent** - Interactions LLM
8. **ProcessTreeEvent** - Relations processus

### Modèles de Données Principaux
- **BaseOSEvent** - Base commune (timestamp, pid, ppid, uid/gid, comm)
- **AgentSession** - Gestion session agent
- **ProcessNode** - Nœud arbre processus
- **SessionTimeline** - Timeline chronologique
- **SecurityRule** - Framework détection

### Dépendances Requises
```
FastAPI              0.104.1    - API REST
Uvicorn              0.24.0     - ASGI server
Pydantic             2.5.0      - Data validation
Python               3.8+       - Runtime
Linux                5.8+       - Ring buffer eBPF support
libbpf               0.7+       - eBPF loader (C)
```

---

## 🧪 COUVERTURE DE TESTS

### 60+ Test Scenarios Requis
- **Part A** (Architecture): 10 tests
- **Part B** (eBPF Probe): 10 tests
- **Part C** (Session Model): 10 tests
- **Part D** (Security Rules): 15 tests
- **Part E** (LLM Correlation): 6 tests
- **Part F** (REST API): 9 tests

### Cas d'Usage Test Clés
- ✅ Création d'événements et validation
- ✅ Construction d'arbres de processus
- ✅ Détection de 4 violations de sécurité réelles
- ✅ Corrélation LLM→OS avec timeline
- ✅ Scénarios attaque (prompt injection)
- ✅ Workflows end-to-end complets

---

## 🎯 CRITÈRES DE SUCCÈS GLOBAL

### Implementation Quality
- ✅ **100% des 6 parties représentées dans le code et la documentation**
- ✅ **Prototype technique validé** sans surinterprétation du runtime eBPF
- ✅ **Type-safe** (Pydantic models)
- ✅ **Performance** (O(1) lookups, logique centrale codée)
- ✅ **Extensible** (règles configurables, architecture modulaire)

### Testing & Validation
- ✅ **Scénarios fonctionnels validés**
- ✅ **Validation de la logique et des API**
- ✅ **Simulation réaliste du workflow** (non-mock)
- ✅ **Détection de violations de sécurité simulées** dans les scénarios end-to-end
- ✅ **Couverture architecturale A-F validée**

### Documentation
- ✅ **Choix de design justifiés**
- ✅ **Algorithmes expliqués**
- ✅ **Cas réels documentés**
- ✅ **API examples fournis**

---

## 📁 FICHIERS DE LIVRAISON

```
src/
├── main.py                      # Orchestration système
├── models/
│   ├── events.py               # 8 types d'événements (Part A)
│   └── session.py              # Session + ProcessTree (Part C)
├── collector/
│   ├── collector.py            # eBPF integration (Part B)
│   └── security.py             # 5 règles sécurité (Part D)
├── ebpf/
│   └── probe.c                 # Kernel probe (Part B)
└── api/
    └── server.py               # 9 endpoints FastAPI (Part F)

tests/
├── test_agentsight.py          # 11 unit tests
├── test_real_comprehensive.py  # End-to-end real test
└── test_50_scenarios.py        # 60+ comprehensive scenarios

docs/
├── EBPF_DESIGN.md              # Deep-dive design choices
└── API_EXAMPLES.md             # Usage examples

PROJECT_SUMMARY.md              # Executive summary
requirements.txt                # Dependencies
```

---

## 🚀 VALIDATION FINALE

**Status**: ✅ **PROTOTYPE TECHNIQUE VALIDÉ**

Le projet satisfait le besoin technique du assessment avec une architecture solide et des validations fonctionnelles réelles, tout en restant honnête sur le plan runtime :
- architecture kernel→userspace documentée et testable
- source eBPF et préflight Linux présentés comme design/validation d’environnement
- session model avec O(1) lookups et hiérarchie de processus
- 5 règles de sécurité opérationnelles dans le flux simulé
- corrélation LLM-OS implémentée au niveau de la session
- API REST exploitable pour inspection et analyse
- validation fonctionnelle de la logique et des scénarios

**Le chargement eBPF live réel reste une étape d’ingénierie future à vérifier sur un host Linux privilégié.**
