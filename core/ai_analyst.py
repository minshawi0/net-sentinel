import os
from collections import defaultdict
from groq import Groq


def summarize_for_ai(parsed_packets, flow_table, source_activity):
    lines = []
    proto_count = defaultdict(int)
    for pkt in parsed_packets:
        proto_count[pkt.get("type", "OTHER")] += 1

    lines.append(f"Total packets: {len(parsed_packets)}")
    lines.append(f"Protocols: {dict(proto_count)}")

    all_ips = set()
    for pkt in parsed_packets:
        if pkt.get("src_ip"): all_ips.add(pkt["src_ip"])
        if pkt.get("dst_ip"): all_ips.add(pkt["dst_ip"])
    lines.append(f"IPs seen: {sorted(all_ips)}")

    lines.append("\nSOURCE ACTIVITY:")
    for ip, data in source_activity.items():
        duration = (data["last_seen"] or 0) - (data["first_seen"] or 0)
        lines.append(
            f"  {ip} | TCP ports: {sorted(data['tcp_ports'])} | "
            f"UDP ports: {sorted(data['udp_ports'])} | "
            f"ICMP echo: {data['icmp_echo_count']} | "
            f"ICMP unreachable ports: {sorted(data['icmp_unreachable_ports'])} | "
            f"Duration: {duration:.2f}s"
        )

    lines.append("\nTOP FLOWS:")
    sorted_flows = sorted(
        flow_table.items(),
        key=lambda x: x[1]["packet_count"],
        reverse=True
    )[:5]
    for key, flow in sorted_flows:
        src_ip, dst_ip, src_port, dst_port, proto = key
        lines.append(
            f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
            f"[{proto}] pkts={flow['packet_count']} bytes={flow['byte_count']}"
        )

    return "\n".join(lines)


def ai_analyze_pcap(parsed_packets, flow_table, source_activity):
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return (
            "ERROR: GROQ_API_KEY not set.\n\n"
            "Run this in your terminal:\n"
            "  echo \"export GROQ_API_KEY=your-key\" >> ~/.zshrc\n"
            "  source ~/.zshrc\n\n"
            "Get a free key at https://console.groq.com"
        )

    summary = summarize_for_ai(parsed_packets, flow_table, source_activity)

    client = Groq(api_key=api_key)

    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior SOC analyst with 10+ years experience "
                        "in network forensics and threat hunting. "
                        "Be direct, technical, and concise."
                    )
                },
                {
                    "role": "user",
                    "content": f"""Analyze this network capture and produce an incident report with:

1. OVERVIEW — what is happening, roles of each host
2. THREAT ASSESSMENT — attacks detected, attacker IP, MITRE ATT&CK IDs
3. ATTACK TIMELINE — chronological sequence of events
4. VERDICT — severity: CRITICAL / HIGH / MEDIUM / LOW / CLEAN
5. RECOMMENDED ACTIONS — prioritized response steps

PCAP DATA:
{summary}"""
                }
            ],
            max_tokens=1024,
            temperature=0.3
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"ERROR: Groq API error: {str(e)}"
