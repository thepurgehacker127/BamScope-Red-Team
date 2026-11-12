"""
TCP connect port scanner for BamScope Red Team.

Designed for authorized home-lab and private-network discovery.
Reports open TCP ports on a selected IPv4 address.
"""

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Union


# Common TCP ports used by computers, mobile devices,
# servers, network equipment, and other devices.
COMMON_TCP_PORTS = [
    20, 21, 22, 23, 25, 53,
    80, 110, 139, 143, 443, 445,
    548, 554, 587, 631,
    993, 995, 1433, 3306,
    3389, 5000, 5432, 5900,
    8000, 8080, 8443, 9000,
    9100, 27017
]


def _validate_target(target: str) -> str:
    """Accept private, loopback, and link-local IPv4 addresses."""

    try:
        address = ipaddress.IPv4Address(target.strip())
    except ipaddress.AddressValueError:
        raise ValueError("A valid IPv4 address is required.")

    if not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
    ):
        raise ValueError(
            "Scanning is restricted to private or local IPv4 addresses."
        )

    return str(address)


def _get_service_name(port: int) -> str:
    """Return the standard service name when available."""

    try:
        return socket.getservbyport(port, "tcp")
    except (OSError, ValueError):
        return "unknown"


def _check_port(
    target: str,
    port: int,
    timeout: float
) -> Optional[Dict[str, Union[int, str]]]:
    """Check one TCP port and return details if it is open."""

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex((target, port))

            if result == 0:
                return {
                    "ip": target,
                    "port": port,
                    "service": _get_service_name(port),
                    "state": "open"
                }

    except OSError:
        pass

    return None


def scan_host(
    target: str,
    ports: Optional[List[int]] = None,
    timeout: float = 0.7,
    max_workers: int = 24
) -> List[Dict[str, Union[int, str]]]:
    """
    Scan selected TCP ports on one authorized local IPv4 host.

    Returns a list containing open ports only.
    """

    target = _validate_target(target)

    selected_ports = (
        COMMON_TCP_PORTS if ports is None else list(ports)
    )

    if not selected_ports or len(selected_ports) > 256:
        raise ValueError("Choose between 1 and 256 TCP ports.")

    if any(
        type(port) is not int or port < 1 or port > 65535
        for port in selected_ports
    ):
        raise ValueError("Ports must be integers between 1 and 65535.")

    selected_ports = sorted(set(selected_ports))

    if not 0 < timeout <= 5:
        raise ValueError("Timeout must be greater than 0 and at most 5 seconds.")

    if type(max_workers) is not int or not 1 <= max_workers <= 64:
        raise ValueError("Workers must be between 1 and 64.")

    results = []

    with ThreadPoolExecutor(
        max_workers=min(max_workers, len(selected_ports))
    ) as executor:

        tasks = [
            executor.submit(
                _check_port,
                target,
                port,
                timeout
            )
            for port in selected_ports
        ]

        for task in tasks:
            result = task.result()

            if result is not None:
                results.append(result)

    results.sort(key=lambda item: item["port"])

    return results
