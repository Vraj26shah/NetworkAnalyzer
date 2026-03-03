import argparse

from capture import capture_traffic
from offline_analysis import analyze_pkts
from pcap_latency import analyze_pcap_latency


def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Network Traffic Analyzer & Anomaly Detector\n"
            "- Live capture (TCP/IP, DNS, HTTP/HTTPS, ARP)\n"
            "- Real-time alerts (scan, ARP spoof, TTL)\n"
            "- Offline stats and optional PCAP latency view"
        )
    )
    p.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Capture duration seconds (default 30)",
    )
    p.add_argument(
        "--pcap",
        type=str,
        default=None,
        help="Optional Wireshark .pcap path for latency view",
    )

    args = p.parse_args()

    print(f"Capture {args.duration}s. Use network to create traffic.")
    rows = capture_traffic(dur=args.duration)
    print("Capture done.\n")

    df = analyze_pkts(rows)
    if not df.empty:
        print(f"\nTotal packets captured: {len(df)}")

    if args.pcap:
        analyze_pcap_latency(args.pcap)


if __name__ == "__main__":
    main()
