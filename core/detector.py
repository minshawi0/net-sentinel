def detect_all(flow_table, source_activity, arp_ip_to_macs):
    alerts = []
    alerts += detect_udp_scan(source_activity)
    alerts += detect_syn_scan(source_activity, flow_table)
    alerts += detect_icmp_flood(source_activity)
    alerts += detect_null_xmas_fin(flow_table)
    alerts += detect_arp_spoofing(arp_ip_to_macs)
    alerts += detect_ack_scan(source_activity, flow_table)
    alerts += detect_dns_tunneling(flow_table)
    alerts += detect_beaconing(flow_table)
    alerts += detect_slowloris(flow_table)
    alerts += detect_exfiltration(flow_table)
    alerts += detect_port_knocking(source_activity)
    return alerts


# ─── TIER 1 AUTO ────────────────────────────────────────────

def detect_udp_scan(source_activity):
    alerts = []
    for ip, data in source_activity.items():
        if len(data["icmp_unreachable_ports"]) > 15:
            alerts.append({
                "attack": "UDP Port Scan",
                "src_ip": ip,
                "evidence": f"{len(data['icmp_unreachable_ports'])} ICMP unreachable ports",
                "tier": "AUTO",
                "action": "block_ip",
                "mitre": "T1046"
            })
    return alerts


def detect_syn_scan(source_activity, flow_table):
    alerts = []
    for ip, data in source_activity.items():
        syn_only_ports = 0
        for key, flow in flow_table.items():
            if key[0] == ip and key[4] == "TCP":
                flags = flow["flags_seen"]
                if "S" in str(flags) and "A" not in str(flags):
                    syn_only_ports += 1
        if syn_only_ports > 20:
            alerts.append({
                "attack": "TCP SYN Scan",
                "src_ip": ip,
                "evidence": f"{syn_only_ports} SYN-only flows",
                "tier": "AUTO",
                "action": "block_ip",
                "mitre": "T1046"
            })
    return alerts


def detect_icmp_flood(source_activity):
    alerts = []
    for ip, data in source_activity.items():
        duration = (data["last_seen"] or 0) - (data["first_seen"] or 0)
        if data["icmp_echo_count"] > 100 and duration < 3:
            alerts.append({
                "attack": "ICMP Flood",
                "src_ip": ip,
                "evidence": f"{data['icmp_echo_count']} ICMP echo requests in {duration:.1f}s",
                "tier": "AUTO",
                "action": "block_ip_rate_limit",
                "mitre": "T1498.001"
            })
    return alerts


def detect_null_xmas_fin(flow_table):
    alerts = []
    for key, flow in flow_table.items():
        if key[4] != "TCP":
            continue
        for flag_combo in flow["flags_seen"]:
            f = str(flag_combo)
            if f == "0" or f == "":
                alerts.append({"attack": "NULL Scan", "src_ip": key[0],
                    "evidence": "TCP packet with no flags", "tier": "AUTO",
                    "action": "block_ip", "mitre": "T1046"})
            elif "F" in f and "U" in f and "P" in f and "A" not in f and "S" not in f:
                alerts.append({"attack": "XMAS Scan", "src_ip": key[0],
                    "evidence": "FIN+URG+PSH flags set", "tier": "AUTO",
                    "action": "block_ip", "mitre": "T1046"})
    return alerts


def detect_arp_spoofing(arp_ip_to_macs):
    alerts = []
    for ip, macs in arp_ip_to_macs.items():
        if len(macs) > 1:
            alerts.append({
                "attack": "ARP Spoofing",
                "src_ip": ip,
                "evidence": f"IP {ip} claimed by MACs: {macs}",
                "tier": "AUTO",
                "action": "drop_arp",
                "mitre": "T1557.002"
            })
    return alerts
def detect_ack_scan(source_activity, flow_table):
    alerts = []
    for ip, data in source_activity.items():
        ack_only_flows = 0
        for key, flow in flow_table.items():
            if key[0] == ip and key[4] == "TCP":
                flags = flow["flags_seen"]
                # ACK set, no SYN anywhere in this flow, no legitimate handshake
                for f in flags:
                    f_str = str(f)
                    if "A" in f_str and "S" not in f_str and flow["packet_count"] >= 1:
                        ack_only_flows += 1
                        break
        if ack_only_flows > 5:
            alerts.append({
                "attack": "TCP ACK Scan",
                "src_ip": ip,
                "evidence": f"{ack_only_flows} ACK-only flows with no prior handshake",
                "tier": "AUTO",
                "action": "block_ip",
                "mitre": "T1046",
                "note": "Attacker is mapping firewall rules, not checking open ports"
            })
    return alerts

# ─── TIER 2 HUMAN ───────────────────────────────────────────

def detect_dns_tunneling(flow_table):
    alerts = []
    # DNS tunneling detection requires per-packet DNS data
    # This is a placeholder — wire into parsed packets DNS fields
    return alerts


def detect_beaconing(flow_table):
    alerts = []
    from collections import defaultdict
    import statistics

    dst_times = defaultdict(list)
    for key, flow in flow_table.items():
        if key[4] in ("TCP", "UDP"):
            dst_times[(key[0], key[1], key[3])].append(flow["start_time"])

    for (src, dst, port), times in dst_times.items():
        if len(times) < 5:
            continue
        times.sort()
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals:
            continue
        avg = sum(intervals) / len(intervals)
        try:
            stdev = statistics.stdev(intervals)
        except:
            stdev = 0
        if 10 < avg < 300 and stdev < 5:
            alerts.append({
                "attack": "C2 Beaconing",
                "src_ip": src,
                "dst_ip": dst,
                "evidence": f"Regular interval: {avg:.1f}s ± {stdev:.1f}s over {len(times)} connections",
                "tier": "HUMAN",
                "options": ["Block Destination IP", "Block Domain", "Isolate Host", "Investigate"],
                "mitre": "T1071"
            })
    return alerts


def detect_slowloris(flow_table):
    alerts = []
    for key, flow in flow_table.items():
        if key[4] == "TCP" and key[3] in (80, 443, 8080):
            duration = (flow["end_time"] or 0) - (flow["start_time"] or 0)
            avg_payload = (sum(flow["payload_sizes"]) / len(flow["payload_sizes"])
                          ) if flow["payload_sizes"] else 0
            if duration > 30 and avg_payload < 50 and flow["packet_count"] > 10:
                alerts.append({
                    "attack": "Slowloris DoS",
                    "src_ip": key[0],
                    "evidence": f"Long HTTP connection ({duration:.0f}s), avg payload {avg_payload:.0f}B",
                    "tier": "HUMAN",
                    "options": ["Block Source IP", "Rate Limit", "Alert Only", "Investigate"],
                    "mitre": "T1499.001"
                })
    return alerts


def detect_exfiltration(flow_table):
    alerts = []
    THRESHOLD_BYTES = 50 * 1024 * 1024  # 50MB
    for key, flow in flow_table.items():
        if flow["byte_count"] > THRESHOLD_BYTES:
            alerts.append({
                "attack": "Possible Data Exfiltration",
                "src_ip": key[0],
                "dst_ip": key[1],
                "evidence": f"Large outbound transfer: {flow['byte_count'] / 1024 / 1024:.1f}MB",
                "tier": "HUMAN",
                "options": ["Block Destination IP", "Block Domain", "Isolate Host", "Throttle & Monitor"],
                "mitre": "T1048"
            })
    return alerts


def detect_port_knocking(source_activity):
    alerts = []
    for ip, data in source_activity.items():
        total_ports = len(data["tcp_ports"])
        duration = (data["last_seen"] or 0) - (data["first_seen"] or 0)
        if 3 <= total_ports <= 10 and duration > 5:
            alerts.append({
                "attack": "Possible Port Knocking",
                "src_ip": ip,
                "evidence": f"Sequential access to {total_ports} ports over {duration:.1f}s",
                "tier": "HUMAN",
                "options": ["Block Source IP", "Alert & Monitor", "Log & Investigate"],
                "mitre": "T1205.001"
            })
    return alerts
