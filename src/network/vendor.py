"""
MAC address vendor lookup using the local ieeeoui database when available,
with an expanded built-in fallback list (strong focus on mobile devices).
"""

import os
import re
from typing import Optional

# Expanded fallback list (prefix -> vendor)
# Includes many common mobile / phone / tablet vendors
FALLBACK_VENDORS = {
    # --- Apple (iPhone, iPad, Mac) ---
    "00:1E:C2": "Apple",
    "00:23:12": "Apple",
    "00:25:00": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "04:0C:CE": "Apple",
    "28:CF:E9": "Apple",
    "3C:22:FB": "Apple",
    "A4:83:E7": "Apple",
    "AC:DE:48": "Apple",
    "F0:18:98": "Apple",
    "F0:D1:A9": "Apple",
    "DC:A9:04": "Apple",
    "F4:5C:89": "Apple",
    "40:B3:95": "Apple",
    "70:DE:E2": "Apple",
    "F0:C1:F1": "Apple",
    "A8:86:DD": "Apple",
    "BC:3B:AF": "Apple",
    "D0:03:4B": "Apple",
    "E0:B5:5F": "Apple",
    "F0:B3:EC": "Apple",
    "28:E0:2C": "Apple",
    "3C:15:C2": "Apple",
    "64:A3:CB": "Apple",
    "70:48:0F": "Apple",
    "78:31:C1": "Apple",
    "88:66:A5": "Apple",
    "A4:5E:60": "Apple",
    "C8:69:CD": "Apple",
    "D8:1C:79": "Apple",
    "E8:80:2E": "Apple",
    "F0:99:BF": "Apple",
    "F4:1B:A1": "Apple",

    # --- Samsung ---
    "00:12:47": "Samsung",
    "00:15:99": "Samsung",
    "00:16:32": "Samsung",
    "00:17:C9": "Samsung",
    "00:1A:8A": "Samsung",
    "00:1D:25": "Samsung",
    "00:1E:7D": "Samsung",
    "00:21:19": "Samsung",
    "00:23:39": "Samsung",
    "00:23:D6": "Samsung",
    "00:24:54": "Samsung",
    "00:25:66": "Samsung",
    "00:26:37": "Samsung",
    "08:D4:2B": "Samsung",
    "10:1D:C0": "Samsung",
    "14:49:E0": "Samsung",
    "18:3A:2D": "Samsung",
    "20:64:32": "Samsung",
    "24:4B:03": "Samsung",
    "28:98:7B": "Samsung",
    "2C:44:01": "Samsung",
    "30:07:4D": "Samsung",
    "34:23:BA": "Samsung",
    "38:AA:3C": "Samsung",
    "3C:8B:FE": "Samsung",
    "40:0E:85": "Samsung",
    "44:80:EB": "Samsung",
    "50:01:BB": "Samsung",
    "5C:0A:5B": "Samsung",
    "60:A1:0A": "Samsung",
    "64:B3:10": "Samsung",
    "70:F9:27": "Samsung",
    "78:1F:DB": "Samsung",
    "80:57:19": "Samsung",
    "84:25:DB": "Samsung",
    "88:32:9B": "Samsung",
    "8C:71:F8": "Samsung",
    "90:18:7C": "Samsung",
    "A0:0B:BA": "Samsung",
    "A8:06:00": "Samsung",
    "B4:79:A7": "Samsung",
    "C0:97:27": "Samsung",
    "C8:BA:94": "Samsung",
    "D0:22:BE": "Samsung",
    "D4:87:D8": "Samsung",
    "E4:58:B8": "Samsung",
    "EC:9B:F3": "Samsung",
    "F0:25:B7": "Samsung",
    "F4:09:D8": "Samsung",
    "F8:04:2E": "Samsung",
    "FC:A1:3E": "Samsung",

    # --- Google (Pixel) ---
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "54:60:09": "Google",
    "F4:F5:D8": "Google",
    "DA:A1:19": "Google",
    "3C:28:6D": "Google",
    "94:EB:2C": "Google",
    "F8:8F:CA": "Google",

    # --- Xiaomi / Redmi / POCO ---
    "00:9E:C8": "Xiaomi",
    "0C:1D:AF": "Xiaomi",
    "14:F6:5A": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "34:80:B3": "Xiaomi",
    "3C:BD:3E": "Xiaomi",
    "50:8F:4C": "Xiaomi",
    "64:09:80": "Xiaomi",
    "64:B4:73": "Xiaomi",
    "68:DF:DD": "Xiaomi",
    "74:23:44": "Xiaomi",
    "78:02:F8": "Xiaomi",
    "7C:1D:D9": "Xiaomi",
    "8C:BE:BE": "Xiaomi",
    "9C:99:A0": "Xiaomi",
    "A4:DA:32": "Xiaomi",
    "AC:F7:F3": "Xiaomi",
    "B0:E2:35": "Xiaomi",
    "C4:0B:CB": "Xiaomi",
    "D4:97:0B": "Xiaomi",
    "F8:A4:5F": "Xiaomi",
    "FC:64:BA": "Xiaomi",

    # --- Huawei ---
    "00:18:82": "Huawei",
    "00:1E:10": "Huawei",
    "00:25:68": "Huawei",
    "00:25:9E": "Huawei",
    "00:34:FE": "Huawei",
    "00:46:4B": "Huawei",
    "00:66:4B": "Huawei",
    "00:E0:FC": "Huawei",
    "04:B0:E7": "Huawei",
    "08:19:A6": "Huawei",
    "0C:37:DC": "Huawei",
    "10:1B:54": "Huawei",
    "20:08:BE": "Huawei",
    "24:09:95": "Huawei",
    "28:31:52": "Huawei",
    "2C:AB:00": "Huawei",
    "30:D1:7E": "Huawei",
    "34:6B:D3": "Huawei",
    "3C:F8:08": "Huawei",
    "40:4D:8E": "Huawei",
    "48:46:FB": "Huawei",
    "4C:54:99": "Huawei",
    "50:01:D9": "Huawei",
    "54:25:EA": "Huawei",
    "5C:B3:95": "Huawei",
    "64:16:F0": "Huawei",
    "70:72:3C": "Huawei",
    "74:A0:63": "Huawei",
    "7C:11:CB": "Huawei",
    "80:71:7A": "Huawei",
    "88:53:D4": "Huawei",
 "90:17:AC": "Huawei",
    "9C:28:EF": "Huawei",
    "A0:8C:FD": "Huawei",
    "A4:BA:76": "Huawei",
    "AC:E2:15": "Huawei",
    "B0:E1:7E": "Huawei",
    "C8:D1:5E": "Huawei",
    "D4:6A:A8": "Huawei",
    "E8:08:8B": "Huawei",
    "F4:C7:14": "Huawei",
    "FC:48:EF": "Huawei",

    # --- OnePlus ---
    "94:65:2D": "OnePlus",
    "C0:EE:FB": "OnePlus",
    "E8:B5:41": "OnePlus",

    # --- Oppo ---
    "00:1A:3F": "Oppo",
    "18:D7:17": "Oppo",
    "2C:5B:B8": "Oppo",
    "A0:91:A2": "Oppo",
    "B8:37:65": "Oppo",
    "E4:47:90": "Oppo",

    # --- Vivo ---
    "00:6B:9E": "Vivo",
    "18:E7:77": "Vivo",
    "2C:4D:54": "Vivo",
    "3C:F5:91": "Vivo",
    "70:8A:09": "Vivo",
    "9C:A5:C0": "Vivo",
    "C4:66:99": "Vivo",

    # --- Motorola ---
    "00:0A:28": "Motorola",
    "00:0E:C6": "Motorola",
    "00:24:37": "Motorola",
    "14:1A:A3": "Motorola",
    "40:78:69": "Motorola",
    "44:80:EB": "Motorola",
    "5C:0E:8B": "Motorola",
    "60:BE:B5": "Motorola",
    "9C:D3:5B": "Motorola",
    "A4:70:D6": "Motorola",
    "CC:61:E5": "Motorola",
    "E0:75:7D": "Motorola",

    # --- LG ---
    "00:1C:62": "LG",
    "00:1E:75": "LG",
    "00:22:A9": "LG",
    "10:F9:6F": "LG",
    "30:76:6F": "LG",
    "5C:87:9C": "LG",
    "64:89:9A": "LG",
    "70:05:14": "LG",
    "A8:16:B2": "LG",
    "C4:43:8F": "LG",
    "CC:FA:00": "LG",
    "E8:5B:5B": "LG",
    "F8:95:C7": "LG",

    # --- Sony ---
    "00:01:4A": "Sony",
    "00:13:A9": "Sony",
    "00:1A:80": "Sony",
    "00:1D:BA": "Sony",
    "00:24:BE": "Sony",
    "28:0D:FC": "Sony",
    "40:B8:37": "Sony",
    "54:42:49": "Sony",
    "70:9F:2D": "Sony",
    "A8:E3:EE": "Sony",
    "F0:BF:97": "Sony",

    # --- HTC ---
    "00:23:76": "HTC",
    "00:EE:BD": "HTC",
    "2C:8A:72": "HTC",
    "50:2E:5C": "HTC",
    "7C:61:93": "HTC",
    "90:21:55": "HTC",
    "B4:CE:F6": "HTC",
    "E8:99:C4": "HTC",

    # --- Nokia / HMD ---
    "00:14:8C": "Nokia",
    "00:19:4F": "Nokia",
    "04:5C:06": "Nokia",
    "14:C1:26": "Nokia",
    "34:C3:D0": "Nokia",
    "6C:A9:06": "Nokia",
    "A4:77:33": "Nokia",
    "D8:FB:5E": "Nokia",

    # --- Realme ---
    "10:2C:6B": "Realme",
    "5C:A6:E6": "Realme",
    "A8:5B:F7": "Realme",

    # --- Honor ---
    "00:9A:CD": "Honor",
    "20:2B:20": "Honor",
    "70:8A:09": "Honor",

    # --- ASUS (phones + networking) ---
    "00:0C:6E": "ASUS",
    "00:11:D8": "ASUS",
    "00:13:D4": "ASUS",
    "00:17:31": "ASUS",
    "00:1A:92": "ASUS",
    "00:1B:FC": "ASUS",
    "00:1D:60": "ASUS",
    "00:1E:8C": "ASUS",
    "00:22:15": "ASUS",
    "00:23:54": "ASUS",
    "00:24:8C": "ASUS",
    "00:25:22": "ASUS",
    "00:26:18": "ASUS",
    "08:60:6E": "ASUS",
    "1C:87:2C": "ASUS",
    "2C:4D:79": "ASUS",
    "40:B0:34": "ASUS",
    "50:46:5D": "ASUS",
    "60:45:CB": "ASUS",
    "70:4D:7B": "ASUS",
    "74:D0:2B": "ASUS",
    "AC:22:0B": "ASUS",
    "BC:EE:7B": "ASUS",
    "E0:3F:49": "ASUS",

    # --- Virtual / Hypervisors (still useful) ---
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:05:69": "VMware",
    "00:1C:14": "VMware",
    "00:1C:42": "Parallels",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:15:5D": "Microsoft Hyper-V",

    # --- Raspberry Pi ---
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
}


def _normalize_mac(mac: str) -> str:
    """Normalize MAC to uppercase XX:XX:XX:XX:XX:XX format."""
    mac = mac.strip().upper().replace("-", ":")
    if re.fullmatch(r"[0-9A-F]{12}", mac):
        mac = ":".join(mac[i:i+2] for i in range(0, 12, 2))
    return mac


def lookup_vendor(mac: str) -> str:
    """
    Return the vendor name for a MAC address, or empty string if unknown.
    """
    if not mac:
        return ""

    mac = _normalize_mac(mac)
    prefix = mac[:8]  # first 3 octets

    # Try fallback list first (fast)
    if prefix in FALLBACK_VENDORS:
        return FALLBACK_VENDORS[prefix]

    # Try system ieeeoui file if present (common on Kali/Debian)
    oui_paths = [
        "/usr/share/ieee-data/oui.txt",
        "/usr/share/misc/oui.txt",
        "/var/lib/ieee-data/oui.txt",
    ]

    for path in oui_paths:
        if os.path.isfile(path):
            try:
                needle = prefix.replace(":", "-")
                with open(path, "r", errors="ignore") as f:
                    for line in f:
                        if line.startswith(needle):
                            parts = line.split(None, 2)
                            if len(parts) >= 3:
                                return parts[2].strip()
            except Exception:
                pass

    return ""
