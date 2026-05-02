from core.parser import parse_pcap
from core.flow_builder import build_flows
from core.detector import detect_all
from core.ai_analyst import ai_analyze_pcap
import json
import sys
import os
from dotenv import load_dotenv

load_dotenv()

def run(pcap_path):
    print(f"[*] Parsing {pcap_path}...")
    packets = parse_pcap(pcap_path)
    print(f"[*] Parsed {len(packets)} packets")

    print("[*] Building flows...")
    flow_table, source_activity, arp_map = build_flows(packets)

    print("[*] Running detectors...")
    alerts = detect_all(flow_table, source_activity, arp_map)

    print(f"\n[!] {len(alerts)} rule-based alerts found:")
    for alert in alerts:
        print(json.dumps(alert, indent=2, default=str))

    print("\n[*] Running AI analysis...")
    ai_report = ai_analyze_pcap(packets, flow_table, source_activity)
    print("\n" + "="*60)
    print("AI ANALYST REPORT")
    print("="*60)
    print(ai_report)

if __name__ == "__main__":
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else "pcaps/sample.pcap"
    run(pcap_file)
