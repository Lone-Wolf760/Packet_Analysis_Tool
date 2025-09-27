import argparse
import datetime
import time
import io
import signal
import sys
import pandas as pd

from capture import start_capture, stop_capture
from analysis import (
    detect_syn_flood, detect_port_scan, detect_ddos,
    detect_blacklist, detect_unusual_protocol, protocol_distribution
)
from visualize import plot_protocol_distribution, plot_packet_length_distribution
from report import generate_pdf_report

def run_cli(packet_count=None, export_pdf=False, iface=None, save_pdf=True):
    print("🔍 Starting Smart Packet Analyzer (CLI Mode)")

    start_time = time.time()

    if packet_count:  # fixed count capture
        print(f"📡 Capturing {packet_count} packets...")
        start_capture(iface=iface)
        time.sleep(0.5)  # allow sniffer warm-up
        df = stop_capture()
    else:  # continuous mode
        print("📡 Continuous capture started. Press CTRL+C to stop...")
        start_capture(iface=iface)

        def signal_handler(sig, frame):
            print("\n⏹ Capture stopped by user.")
            df = stop_capture()
            process_results(df, start_time, export_pdf, iface, save_pdf)
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        while True:
            time.sleep(1)

    process_results(df, start_time, export_pdf, iface, save_pdf)


def process_results(df, start_time, export_pdf, iface, save_pdf):
    duration = round(time.time() - start_time, 2)

    if df.empty:
        print("❌ No packets captured.")
        return

    print(f"\n✅ Captured {df.shape[0]} packets in {duration} seconds")

    proto_dist = protocol_distribution(df)
    fig1, _ = plot_protocol_distribution(df, show=False)
    syn = detect_syn_flood(df)
    port_scan = detect_port_scan(df)
    ddos = detect_ddos(df)
    bl = detect_blacklist(df)
    up = detect_unusual_protocol(df)
    fig2, _ = plot_packet_length_distribution(df, show=False)

    df["threat_score"] = 0
    if "flags" in df.columns:
        df.loc[df["flags"].str.contains("S", na=False), "threat_score"] += 2
    if not bl.empty:
        df.loc[bl.index, "threat_score"] += 10
    high_threat = df[df["threat_score"] >= 5]

    # Console outputs
    print("\n📊 Protocol Distribution:"); print(proto_dist)
    print("\n🚨 SYN Flood Detection:"); print(syn if not syn.empty else "No SYN Flood detected")
    print("\n🚨 Port Scan Detection:"); print(port_scan if not port_scan.empty else "No Port Scan detected")
    print("\n🚨 DDoS Detection:"); print(ddos if not ddos.empty else "No DDoS detected")
    print("\n🚨 Blacklisted IPs:"); print(bl if not bl.empty else "No blacklisted IPs detected")
    print("\n🚨 Unusual Protocols:"); print(up if not up.empty else "All protocols normal")
    if not high_threat.empty:
        print("\n🔥 High Threat Packets:"); print(high_threat.sort_values("threat_score", ascending=False))
    else:
        print("\n🔥 No high threat packets detected.")

    if export_pdf:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        results = {
            "SYN Flood Detection": syn if not syn.empty else "No SYN Flood detected",
            "Port Scan Detection": port_scan if not port_scan.empty else "No Port Scan detected",
            "DDoS Detection": ddos if not ddos.empty else "No DDoS detected",
            "Blacklisted IPs": bl if not bl.empty else "No blacklisted IPs detected",
            "Unusual Protocols": up if not up.empty else "All protocols normal",
        }
        plots = {"Protocol Distribution": fig1, "Packet Length Distribution": fig2}
        metadata = {
            "timestamp": timestamp,
            "packet_count": df.shape[0],
            "duration": duration,
            "interface": iface or "default"
        }

        pdf_buffer = io.BytesIO()
        generate_pdf_report(pdf_buffer, df, results, plots, high_threat, metadata)

        if save_pdf:
            filename = f"packet_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            with open(filename, "wb") as f:
                f.write(pdf_buffer.getbuffer())
            print(f"\n📄 PDF Report saved: {filename}")
        else:
            print("\n📄 PDF generated in memory (not saved).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--packets", type=int, help="Number of packets to capture (omit for continuous mode)")
    parser.add_argument("--pdf", action="store_true", help="Export PDF report")
    parser.add_argument("--iface", type=str, help="Network interface")
    parser.add_argument("--no-save", action="store_true", help="Do not save PDF to disk")
    args = parser.parse_args()

    run_cli(packet_count=args.packets, export_pdf=args.pdf, iface=args.iface, save_pdf=not args.no_save)
