from typing import Dict

from scapy.all import ARP


def detect_port_scan(row: Dict, track: Dict[str, set], limit: int = 20) -> None:
    src = row.get("src_ip")
    dport = row.get("dst_port")
    proto = row.get("protocol")

    if proto not in {"TCP", "HTTP", "HTTPS", "UDP"}:
        return
    if not src or dport is None:
        return

    track.setdefault(src, set()).add(dport)
    if len(track[src]) == limit:
        print(
            f"[ALERT] Port scan: {src} hit "
            f"{len(track[src])} unique destination ports"
        )


def detect_arp_spoof(row: Dict, pkt, arp_map: Dict[str, str]) -> None:
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]
    ip = arp.psrc
    mac = arp.hwsrc

    if ip in arp_map and arp_map[ip] != mac:
        print(
            f"[ALERT] ARP spoof: {ip} was {arp_map[ip]} "
            f"now claims {mac}"
        )
    else:
        arp_map[ip] = mac


def detect_ttl_anom(
    row: Dict, ttl_base: Dict[str, int], limit: int = 20, low: int = 16
) -> None:
    src = row.get("src_ip")
    ttl = row.get("ttl")
    if src is None or ttl is None:
        return

    if src not in ttl_base:
        ttl_base[src] = ttl
        return

    base = ttl_base[src]
    if abs(ttl - base) >= limit or ttl <= low:
        print(
            f"[ALERT] Abnormal TTL from {src}: now={ttl}, base={base}"
        )

