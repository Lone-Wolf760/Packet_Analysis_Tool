from scapy.all import IP, TCP, UDP, ICMP

def parse_packet(pkt):
    """
    Convert a Scapy packet into a dictionary for analysis.
    """
    parsed = {}
    if IP in pkt:
        parsed["src"] = pkt[IP].src
        parsed["dst"] = pkt[IP].dst
        parsed["protocol"] = pkt[IP].proto
        parsed["length"] = len(pkt)

        # Map protocol numbers to names
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        parsed["protocol"] = proto_map.get(pkt[IP].proto, str(pkt[IP].proto))

        if TCP in pkt:
            parsed["flags"] = str(pkt[TCP].flags)
            parsed["dst_port"] = pkt[TCP].dport
        elif UDP in pkt:
            parsed["flags"] = None
            parsed["dst_port"] = pkt[UDP].dport
        elif ICMP in pkt:
            parsed["flags"] = None
            parsed["dst_port"] = None
    return parsed
