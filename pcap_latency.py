from typing import Dict, Tuple

import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import IP, TCP, rdpcap


def analyze_pcap_latency(path: str) -> None:
    print(f"\nPCAP: {path}")
    try:
        pkts = rdpcap(path)
    except FileNotFoundError:
        print(f"No such file: {path}")
        return
    except Exception as e:
        print(f"PCAP read error: {e}")
        return

    times: Dict[Tuple[str, str, int], Dict[str, float]] = {}

    for p in pkts:
        if not p.haslayer(IP) or not p.haslayer(TCP):
            continue
        ip = p[IP]
        tcp = p[TCP]
        key = (ip.src, ip.dst, int(tcp.dport))
        t = float(p.time)

        flg = tcp.flags
        if flg & 0x02 and not (flg & 0x10):
            times.setdefault(key, {})["syn"] = min(
                t, times.get(key, {}).get("syn", t)
            )
        if flg & 0x10:
            times.setdefault(key, {})["ack"] = min(
                t, times.get(key, {}).get("ack", t)
            )

    rows = []
    for (src, dst, dport), tmap in times.items():
        syn_t = tmap.get("syn")
        ack_t = tmap.get("ack")
        if syn_t is not None and ack_t is not None and ack_t >= syn_t:
            lat_ms = (ack_t - syn_t) * 1000.0
            rows.append(
                {
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": dport,
                    "handshake_latency_ms": lat_ms,
                }
            )

    if not rows:
        print("No TCP handshake latency found.")
        return

    df = pd.DataFrame(rows)
    df.sort_values("handshake_latency_ms", ascending=False, inplace=True)

    print("\nTop 10 TCP flows by handshake latency:")
    print(df.head(10).to_string(index=False))

    plt.figure(figsize=(8, 5))
    df["handshake_latency_ms"].head(50).plot(kind="bar")
    plt.ylabel("Handshake latency (ms)")
    plt.title("Top 50 TCP handshake latencies")
    plt.tight_layout()
    plt.show()

