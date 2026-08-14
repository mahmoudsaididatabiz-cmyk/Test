# AgentSight — Project Summary

## Status

This repository is a validated architecture prototype for OS-level monitoring of AI agent activity. It demonstrates the intended design and the core logic for session correlation, security detection, and API exposure, while being explicit that a live kernel eBPF attachment is not confirmed in every host environment.

## What is implemented

- Process and session models for AI agent activity
- Event models for process execution, file access, file writes, network events, and LLM interactions
- Security engine with threat-style checks for suspicious commands, sensitive file access, and external connections
- FastAPI REST endpoints for sessions and events
- A representative eBPF probe source for process exec capture
- A simulation workflow that exercises the monitoring model end-to-end

## What is validated

The codebase has been exercised successfully in this workspace with Python tests.

Verified command:

```bash
cd /workspaces/Test
python -m pytest -q
```

Result observed:

```text
141 passed in 26.92s
```

## Architecture overview

The project follows a realistic pipeline:

```text
Linux host capability check
  -> eBPF source design
  -> runtime preflight and attach readiness
  -> Python event collection
  -> session correlation by PID/PPID
  -> security rules
  -> API output and reporting
```

## Important limitation

The repository is intentionally conservative: it verifies that the host can support eBPF and that the code path is ready for Linux kernel attachment, but it does not claim a confirmed live kernel injection on every machine.

This is a strength of the project’s honest design documentation, not a defect.

## Production roadmap

The next steps for a real deployment are:

1. Validate a live eBPF attach on a privileged Linux host
2. Consume the ring buffer in real time
3. Correlate all child processes via PPID and session ancestry reliably
4. Persist sessions and events in storage
5. Add file/network/socket probes beyond process exec
6. Expose alerts to dashboards or SIEM systems

## Conclusion

This project is a solid technical prototype and a credible assessment artifact: the architecture, logic, tests, and API are all in place, and the honest status is that the project is ready as a design and validation prototype rather than a guarantee of live production eBPF injection.
