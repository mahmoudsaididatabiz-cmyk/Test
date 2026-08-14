import os
import platform

import pytest

from src.collector.collector import BPFEventCollector


@pytest.mark.skipif(platform.system().lower() != "linux", reason="Linux-only eBPF integration")
def test_bpf_runtime_preflight_reports_linux_capability():
    collector = BPFEventCollector()
    status = collector.check_kernel_injection_capabilities()

    assert status["platform"] == "Linux"
    assert "kernel_version" in status
    assert "bpf_supported" in status
    assert "injected" in status
    assert "reason" in status


@pytest.mark.skipif(platform.system().lower() != "linux", reason="Linux-only eBPF integration")
def test_collectors_support_real_linux_fallbacks():
    collector = BPFEventCollector()

    file_events = collector.collect_linux_file_events(pid=os.getpid())
    network_events = collector.collect_linux_network_events()

    assert isinstance(file_events, list)
    assert isinstance(network_events, list)


@pytest.mark.skipif(platform.system().lower() != "linux", reason="Linux-only eBPF integration")
def test_ring_buffer_polling_handles_sequence_drops():
    collector = BPFEventCollector()

    raw_events = [
        {"sequence": 1, "pid": 1001, "ppid": 1, "uid": 1000, "gid": 1000, "comm": "python", "filename": "/usr/bin/python3"},
        {"sequence": 3, "pid": 1002, "ppid": 1001, "uid": 1000, "gid": 1000, "comm": "bash", "filename": "/bin/bash"},
    ]

    decoded = collector.poll_ring_buffer(raw_events)

    assert len(decoded) == 2
    assert collector.lost_events_count == 1
    assert collector.last_sequence == 3
