"""
Network interface detection utilities for BamScope Red Team.
"""

import psutil
from typing import List, Dict


def get_network_interfaces() -> List[Dict[str, str]]:
    """
    Return a list of usable network interfaces.
    Each item contains: name, ip, netmask (if available).
    """
    interfaces = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for name, snic_list in addrs.items():
        # Skip interfaces that are down
        if name in stats and not stats[name].isup:
            continue

        ip = None
        netmask = None

        for snic in snic_list:
            # AF_INET = IPv4
            if snic.family.name == "AF_INET" or snic.family == 2:
                ip = snic.address
                netmask = snic.netmask
                break

        # Skip loopback for scanning targets (we still show it)
        interfaces.append({
            "name": name,
            "ip": ip or "No IPv4",
            "netmask": netmask or "",
        })

    # Sort so real interfaces appear first
    interfaces.sort(key=lambda x: (x["ip"] == "No IPv4", x["name"] == "lo", x["name"]))
    return interfaces


def get_interface_names() -> List[str]:
    """Return just the interface names for combo boxes."""
    return [iface["name"] for iface in get_network_interfaces()]
