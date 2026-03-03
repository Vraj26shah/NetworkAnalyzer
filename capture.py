from collections import defaultdict
import time
from typing import Dict, List, Optional

from scapy.all import (
    ARP,
    DNS,
    DNSRR,
    IP,
    TCP,
    UDP,
    Raw,
    sniff,
)


pkts_mem: List[Dict] = []
port_scan: Dict[str, set] = defaultdict(set)
arp_map: Dict[str, str] = {}
ttl_base: Dict[str, int] = {}


def proto_of(pkt) -> str:
    if pkt.haslayer(ARP):
        return "ARP"

    if pkt.haslayer(IP):
        if pkt.haslayer(DNS):
            return "DNS"
        if pkt.haslayer(TCP):
            d = pkt[TCP].dport
            s = pkt[TCP].sport
            ports = {d, s}
            if 80 in ports:
                return "HTTP"
            if 443 in ports:
                return "HTTPS"
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        return "IP"

    return type(pkt).__name__


def row_of(pkt) -> Dict:
    import anomalies

    ts = time.time()
    proto = proto_of(pkt)

    src: Optional[str] = None
    dst: Optional[str] = None
    sport: Optional[int] = None
    dport: Optional[int] = None
    ttl: Optional[int] = None
    info: Optional[str] = None

    if pkt.haslayer(IP):
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        ttl = int(ip.ttl)

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport = int(tcp.sport)
            dport = int(tcp.dport)
            if proto in {"HTTP", "HTTPS"} and pkt.haslayer(Raw):
                data = bytes(pkt[Raw])[:80]
                info = data.decode(errors="ignore")
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport = int(udp.sport)
            dport = int(udp.dport)
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qd is not None:
                    info = f"DNS query {dns.qd.qname.decode(errors='ignore')}"
                elif dns.qr == 1 and dns.an is not None:
                    ans = []
                    for i in range(dns.ancount):
                        rr = dns.an[i]
                        if isinstance(rr, DNSRR):
                            ans.append(rr.rdata)
                    info = f"DNS resp {ans}"

    elif pkt.haslayer(ARP):
        arp = pkt[ARP]
        src = arp.psrc
        dst = arp.pdst
        info = f"ARP op={arp.op} src={arp.hwsrc} dst={arp.hwdst}"

    row = {
        "timestamp": ts,
        "protocol": proto,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "ttl": ttl,
        "info": info,
    }

    anomalies.detect_port_scan(row, port_scan)
    anomalies.detect_arp_spoof(row, pkt, arp_map)
    anomalies.detect_ttl_anom(row, ttl_base)

    return row


def on_pkt(pkt):
    r = row_of(pkt)
    pkts_mem.append(r)


def capture_traffic(dur: int = 30) -> List[Dict]:
    pkts_mem.clear()
    try:
        sniff(timeout=dur, prn=on_pkt, store=0)
    except PermissionError:
        print(
            "[ERROR] Need root for packet capture.\n"
            "On Linux, run: sudo python3 network_traffic_analyzer1.py"
        )
        return []
    return list(pkts_mem)

