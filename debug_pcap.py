from scapy.all import rdpcap, IP, TCP, ARP
import sys

pcap_file = sys.argv[1]
packets = rdpcap(pcap_file)

print(f"Total packets: {len(packets)}\n")

for i, pkt in enumerate(packets):
    if TCP in pkt:
        flags = pkt[TCP].flags
        print(f"Packet {i+1} | {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} | Flags: {flags} | Type: {type(flags)} | Str: {str(flags)}")
    elif ARP in pkt:
        print(f"Packet {i+1} | ARP | {pkt[ARP].psrc} -> {pkt[ARP].pdst} | op: {pkt[ARP].op}")
