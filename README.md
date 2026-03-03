Network Traffic Analyzer
========================

### 1. What this project does

- **Capture live packets** (TCP, UDP, HTTP/HTTPS, DNS, ARP) using Scapy.
- **Print real‑time alerts**:
  - port‑scan style behavior,
  - ARP spoofing (IP → MAC changes),
  - abnormal TTL values.
- **Offline analysis** after capture:
  - traffic spikes per protocol (packet rate),
  - top source / destination IPs,
  - simple offline port‑scan pattern,
  - protocol‑usage bar chart.
- **Optional PCAP mode**:
  - read a Wireshark `.pcap`,
  - estimate TCP handshake latency per flow,
  - show slowest handshakes and a latency bar chart.

Main entry point: `network_traffic_analyzer1.py`


### 2. Requirements

- Python 3.10+ (tested with 3.12)
- Linux (for raw socket sniffing with Scapy)
- `scapy`, `pandas`, `matplotlib`

Install with `pip` using the provided `requirements.txt`.


### 3. Setup (recommended: virtual environment)

From the project folder:

```bash
cd /path/to/NetworkTraffic_Analyzer-main

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

This installs:

- `scapy` – packet capture and parsing
- `pandas` – offline analysis
- `matplotlib` – charts


### 4. Run live capture

Packet capture requires **root** on Linux because it uses raw sockets.

Activate the venv first:

```bash
cd /path/to/NetworkTraffic_Analyzer-main
source .venv/bin/activate
```

Then run the analyzer with `sudo` using the same Python:

```bash
sudo -E $(which python3) network_traffic_analyzer1.py --duration 30
```

Flags:

- `--duration` (int, optional): capture time in seconds (default `30`).

While it runs:

- browse the web, ping hosts, do DNS lookups, etc. to generate traffic.

Expected output:

- real‑time `[ALERT]` lines for port scans / ARP spoof / TTL anomalies,
- `[INFO]` lines for new source IPs,
- at the end:
  - total packets captured,
  - top source/destination IPs,
  - protocol usage bar chart window (if a GUI is available),
  - `traffic_capture.csv` written in the project folder.


### 5. Run offline PCAP latency analysis

You can also feed a Wireshark capture (`.pcap`) to the script.

Steps:

1. Capture in Wireshark and save as `capture.pcap`.
2. Run:

```bash
cd /path/to/NetworkTraffic_Analyzer-main
source .venv/bin/activate

sudo -E $(which python3) network_traffic_analyzer1.py --pcap capture.pcap
```

Behavior:

- reads the PCAP with Scapy,
- finds TCP SYN and ACK times per (src IP, dst IP, dst port),
- estimates handshake latency in milliseconds,
- prints the top 10 slowest flows,
- draws a bar chart of the highest 50 handshake latencies.


### 6. File overview

- `network_traffic_analyzer1.py`  
  CLI entry point; parses `--duration` / `--pcap`, runs live capture and/or PCAP analysis.

- `capture.py`  
  Uses `scapy.sniff` to collect packets, build small dict rows, and call real‑time anomaly functions.

- `anomalies.py`  
  Stateless helper functions:
  - `detect_port_scan` – counts unique destination ports per source IP,
  - `detect_arp_spoof` – tracks IP → MAC and flags changes,
  - `detect_ttl_anom` – flags large TTL shifts or very low TTL.

- `offline_analysis.py`  
  Turns captured rows into a `pandas` DataFrame, checks for spikes and offline scan patterns, prints top talkers, and plots protocol usage.

- `pcap_latency.py`  
  Reads a `.pcap`, computes TCP handshake latency per flow, prints and plots slowest connections.

- `requirements.txt`  
  Python dependencies (`scapy`, `pandas`, `matplotlib`).


### 7. Notes for interview prep (short explanation)

You can summarize the project like this:

> “I built a small Python‑based network analyzer using Scapy, pandas, and matplotlib.  
> It sniffs live traffic, extracts fields like protocol, IPs, ports, TTL and short payload info, then runs simple real‑time checks for port scans, ARP spoofing, and abnormal TTL.  
> After capture, it loads the data into pandas to detect traffic spikes, list top talkers, and plot protocol usage, while saving everything to CSV.  
> There is also an offline mode that reads Wireshark `.pcap` files and estimates TCP handshake latency per flow, so I can quickly see which connections had the slowest handshakes.”

