"""Shared network reachability checks.

Provides ping and port-check utilities used by multiple supplements
(SSHFP scanning, SSL certificate scanning, etc.).
"""

from __future__ import annotations

import socket
import subprocess


def check_reachable(ip: str, packets: int = 5) -> bool:
    """Check if a host responds to ICMP ping.

    Args:
        ip: IPv4 address string to ping.
        packets: Number of ping packets to send.

    Returns:
        True if all packets were received.
    """
    try:
        result = subprocess.run(
            ["ping", "-n", "-A", "-c", str(packets), "-w", "1", ip],
            capture_output=True,
            text=True,
        )
        return f"{packets} packets transmitted, {packets} received" in result.stdout
    except FileNotFoundError:
        return False


def check_port_open(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Check if a TCP port is open on the host.

    Args:
        ip: IPv4 address string.
        port: TCP port number to check.
        timeout: Connection timeout in seconds.

    Returns:
        True if the port is open and accepting connections.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    finally:
        sock.close()
