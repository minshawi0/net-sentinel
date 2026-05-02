from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR

def parse_pcap(filepath):
    packets = rdpcap(filepath)
    parsed = []

    for pkt in packets:
        record = {"timestamp": float(pkt.time)}

        if ARP in pkt:
            record.update({
                "type": "ARP",
                "src_ip": pkt[ARP].psrc,
                "dst_ip": pkt[ARP].pdst,
                "src_mac": pkt[ARP].hwsrc,
                "op": pkt[ARP].op  # 1=request, 2=reply
            })
            parsed.append(record)
            continue

        if IP not in pkt:
            continue

        record.update({
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "length": len(pkt),
        })

        if TCP in pkt:
            record.update({
                "type": "TCP",
                "src_port": pkt[TCP].sport,
                "dst_port": pkt[TCP].dport,
                "flags": str(pkt[TCP].flags),
                "payload_len": len(pkt[TCP].payload)
            })

        elif UDP in pkt:
            record.update({
                "type": "UDP",
                "src_port": pkt[UDP].sport,
                "dst_port": pkt[UDP].dport,
            })
            if DNS in pkt and pkt[DNS].qr == 0:
                record["dns_query"] = pkt[DNSQR].qname.decode(errors="ignore")
                record["dns_type"] = pkt[DNSQR].qtype

        elif ICMP in pkt:
            record.update({
                "type": "ICMP",
                "icmp_type": pkt[ICMP].type,
                "icmp_code": pkt[ICMP].code,
            })
            # If ICMP unreachable, extract the inner UDP port (for UDP scan detection)
            if pkt[ICMP].type == 3 and pkt[ICMP].code == 3:
                try:
                    inner = pkt[ICMP].payload
                    if UDP in inner:
                        record["inner_dst_port"] = inner[UDP].dport
                        record["inner_src_ip"] = inner[IP].src
                except:
                    pass

        parsed.append(record)

    return parsed
