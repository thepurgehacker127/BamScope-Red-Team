"""
ARP-based host discovery for BamScope Red Team.
"""

from scapy.all import ARP, Ether, srp, conf
from typing import List, Dict
import ipaddress

from network.vendor import lookup_vendor
from network.hostname import resolve_hostname


def arp_scan(target: str, interface: str = None, timeout: int = 2) -> List[Dict[str, str]]:
    """
    Perform an ARP scan and enrich results with vendor and hostname.
    """
    conf.verb = 0

    if interface:
        conf.iface = interface

    try:
        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        answered, _ = srp(packet, timeout=timeout, verbose=0)

        results = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc

            vendor = lookup_vendor(mac)
            hostname = resolve_hostname(ip)

            results.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "status": "Up",
                "method": "ARP"
            })

        results.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))
        return results

    except Exception as e:
        raise RuntimeError(f"ARP scan failed: {e}")
