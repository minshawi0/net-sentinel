from collections import defaultdict

def build_flows(parsed_packets):
    flow_table = defaultdict(lambda: {
        "packet_count": 0,
        "byte_count": 0,
        "start_time": None,
        "end_time": None,
        "flags_seen": set(),
        "payload_sizes": []
    })

    source_activity = defaultdict(lambda: {
        "tcp_ports": set(),
        "udp_ports": set(),
        "icmp_unreachable_ports": set(),
        "icmp_echo_count": 0,
        "first_seen": None,
        "last_seen": None,
        "arp_ips_claimed": set()
    })

    arp_ip_to_macs = defaultdict(set)

    for pkt in parsed_packets:
        src = pkt.get("src_ip")
        ts = pkt.get("timestamp")

        if not src:
            continue

        sa = source_activity[src]
        if sa["first_seen"] is None:
            sa["first_seen"] = ts
        sa["last_seen"] = ts

        ptype = pkt.get("type")

        if ptype == "TCP":
            key = (src, pkt["dst_ip"], pkt["src_port"], pkt["dst_port"], "TCP")
            f = flow_table[key]
            f["packet_count"] += 1
            f["byte_count"] += pkt.get("length", 0)
            f["start_time"] = f["start_time"] or ts
            f["end_time"] = ts
            f["flags_seen"].add(pkt.get("flags", ""))
            f["payload_sizes"].append(pkt.get("payload_len", 0))
            sa["tcp_ports"].add(pkt["dst_port"])

        elif ptype == "UDP":
            key = (src, pkt["dst_ip"], pkt["src_port"], pkt["dst_port"], "UDP")
            f = flow_table[key]
            f["packet_count"] += 1
            f["byte_count"] += pkt.get("length", 0)
            f["start_time"] = f["start_time"] or ts
            f["end_time"] = ts
            sa["udp_ports"].add(pkt["dst_port"])

        elif ptype == "ICMP":
            if pkt.get("icmp_type") == 8:
                sa["icmp_echo_count"] += 1
            if pkt.get("icmp_type") == 3 and pkt.get("icmp_code") == 3:
                if "inner_dst_port" in pkt:
                    source_activity[pkt["inner_src_ip"]]["icmp_unreachable_ports"].add(
                        pkt["inner_dst_port"]
                    )

        elif ptype == "ARP":
            if pkt.get("op") == 2:  # ARP reply
                arp_ip_to_macs[pkt["src_ip"]].add(pkt["src_mac"])

    return flow_table, source_activity, arp_ip_to_macs

