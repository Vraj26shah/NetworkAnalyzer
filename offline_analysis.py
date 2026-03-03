from collections import Counter
from typing import Dict, List
import os

os.environ.setdefault(
    "MPLCONFIGDIR",
    os.path.join(os.path.dirname(__file__), ".matplotlib_cache"),
)

import matplotlib.pyplot as plt
import pandas as pd


def analyze_pkts(rows: List[Dict]) -> pd.DataFrame:
    """Offline stats and simple anomaly checks on captured rows."""
    if not rows:
        print("No packets captured.")
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")

    win = "5s"
    rate_limit = 50

    for p in ["TCP", "UDP", "HTTP", "HTTPS", "DNS"]:
        p_df = df[df["protocol"] == p]
        if not p_df.empty:
            rate = p_df.resample(win, on="timestamp").size()
            spikes = rate[rate > rate_limit]
            for t, v in spikes.items():
                print(f"[ALERT] {v} {p} pkts in {win} at {t}")

    seen = set()
    for ip in df["src_ip"].dropna().unique():
        if ip not in seen:
            print(f"[INFO] New src: {ip}")
        seen.add(ip)

    tcp_df = df[df["protocol"].isin(["TCP", "HTTP", "HTTPS"])]
    for ip, grp in tcp_df.groupby("src_ip"):
        ports = grp["dst_port"].nunique()
        if ports > 50:
            print(f"[ALERT] Offline port scan: {ip} hit {ports} ports")

    counts = Counter(df["protocol"])
    if counts:
        plt.figure(figsize=(8, 6))
        pd.Series(counts).plot(kind="bar")
        plt.title("Protocol usage")
        plt.xlabel("Protocol")
        plt.ylabel("Count")
        plt.tight_layout()
        plt.show()

    if "src_ip" in df.columns:
        print("\nTop src IPs:")
        print(df["src_ip"].value_counts().head(5))

    if "dst_ip" in df.columns:
        print("\nTop dst IPs:")
        print(df["dst_ip"].value_counts().head(5))

    df.to_csv("traffic_capture.csv", index=False)
    print("Saved CSV: traffic_capture.csv")

    return df

