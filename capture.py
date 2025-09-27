from scapy.all import AsyncSniffer
import pandas as pd
import time
from parser import parse_packet

packets_list = []
sniffer = None  # Global reference to AsyncSniffer

def packet_handler(pkt):
    parsed = parse_packet(pkt)
    if parsed:
        parsed["timestamp"] = time.time()
        packets_list.append(parsed)

def start_capture(iface=None):
    """
    Start live packet capture (continuous until stopped).
    """
    global packets_list, sniffer
    packets_list = []
    sniffer = AsyncSniffer(prn=packet_handler, iface=iface, store=False)
    sniffer.start()

def stop_capture():
    """
    Stop live packet capture and return DataFrame.
    """
    global sniffer
    if sniffer:
        sniffer.stop()
    return pd.DataFrame(packets_list)
