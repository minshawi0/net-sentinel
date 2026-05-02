# NetSentinel

A Python-based network threat detection tool that analyzes live and captured network traffic, identifies malicious patterns, and provides AI-assisted analysis for SOC workflows.

---

## What It Does

NetSentinel parses PCAP files and live traffic, runs them through a detection engine, and flags suspicious activity across two tiers:

- **AUTO** — high-confidence threats that trigger immediate alerts (UDP Port Scan, TCP SYN Scan, ICMP Flood, NULL/XMAS/FIN Scan, ARP Spoofing, TCP ACK Scan)
- **HUMAN** — threats that require analyst review before action (DNS Tunneling, C2 Beaconing, Slowloris, Data Exfiltration, Port Knocking)

Each alert includes a MITRE ATT&CK mapping and can be escalated to an AI analyst for a full report.

---

## Stack

- **Python 3**
- **Scapy** — packet parsing and flow analysis
- **PyQt5** — desktop UI
- **Groq API** (llama-3.1-8b-instant) — AI-powered threat analysis

---

## Project Structure

```
net-sentinel/
├── core/
│   ├── parser.py          # PCAP ingestion and packet parsing
│   ├── flow_builder.py    # Network flow reconstruction
│   ├── detector.py        # Detection engine (11 detectors)
│   └── ai_analyst.py      # Groq API integration
├── ui/
│   ├── app.py             # Main PyQt5 interface
│   └── ai_report_window.py
├── main.py
├── requirements.txt
└── .gitignore
```

---

## Setup

```bash
# Clone the repo
git clone https://github.com/minshawi0/net-sentinel.git
cd net-sentinel

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set your Groq API key
export GROQ_API_KEY=your_key_here

# Run
python3 ui/app.py
```

---

## Detections Mapped to MITRE ATT&CK

| Detection | MITRE TTP |
|---|---|
| TCP SYN Scan | T1046 |
| UDP Port Scan | T1046 |
| NULL / XMAS / FIN Scan | T1046 |
| TCP ACK Scan | T1046 |
| ICMP Flood | T1498 |
| ARP Spoofing | T1557.002 |
| DNS Tunneling | T1071.004 |
| C2 Beaconing | T1071 |
| Slowloris | T1499.001 |
| Data Exfiltration | T1041 |
| Port Knocking | T1205.001 |

---

## Status

Active development. Currently running on Kali Linux in a virtualized environment.
Planned expansion to 35 detectors.
