"""
ARP-based host discovery for BamScope Red Team.
"""

from scapy.all import ARP, Ether, srp, conf
from typing import List, Dict
import ipaddress


def arp_scan(target: str, interface: str = None, timeout: int = 2) -> List[Dict[str, str]]:
    """
    Perform an ARP scan on the given target (CIDR, IP, or range).

    Returns a list of dictionaries:
    [
        {
            "ip": "192.168.1.10",
            "mac": "aa:bb:cc:dd:ee:ff",
            "method": "ARP"
        },
        ...
    ]
    """
    conf.verb = 0  # silence Scapy output

    if interface:
        conf.iface = interface

    try:
        # Build ARP request
        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # Send and receive
        answered, _ = srp(packet, timeout=timeout, verbose=0)

        results = []
        for sent, received in answered:
            results.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "hostname": "",
                "vendor": "",
                "status": "Up",
                "method": "ARP"
            })

        # Sort by IP
        results.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))
        return results

    except Exception as e:
        raise RuntimeError(f"ARP scan failed: {e}")
