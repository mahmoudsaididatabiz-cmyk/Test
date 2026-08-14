"""
eBPF probes for OS-level event capture.
"""

# Note: The .c file cannot be directly imported.
# See probe.c for the actual eBPF source code.
# In production, this would be compiled to .o and loaded via libbpf or bcc.

__all__ = []
