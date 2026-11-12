"""
Hostname resolution helpers.
"""

import socket
from typing import Optional


def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    """
    Try to resolve a hostname for the given IP address.
    Returns empty string if resolution fails.
    """
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return ""
