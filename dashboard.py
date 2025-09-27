import streamlit as st
import pandas as pd
import datetime
import time
import io

from capture import start_capture, stop_capture
from analysis import (
    detect_syn_flood, detect_port_scan, detect_ddos,
    detect_blacklist, detect_unusual_protocol
)
from visualize import plot_protocol_distribution, plot_packet_length_distribution
from ml_model import load_model, predict_live
from report import generate_pdf_report

st.set_page_config(page_title="Smart Packet Analyzer", layout="wide")
st.title("🔍 Smart Packet Analyzer Dashboard")

# Sidebar
iface = st.sidebar.text_input("Network Interface (leave blank for default)", value="")
model_loaded = st.sidebar.checkbox("Load ML Model", value=True)

# Session state
if "capturing" not in st.session_state:
    st.session_state.capturing = False
if "captured_df" not in st.session_state:
    st.session_state.captured_df = pd.DataFrame()

# Start Capture
if st.button("▶️ Start Capture") and not st.session_state.capturing:
    st.session_state.capturing = True
    start_capture(iface=iface if iface else None)
    st.success("✅ Capture started. Generating live traffic...")

# Stop Capture
if st.button("⏹ Stop Capture") and st.session_state.capturing:
    st.session_state.capturing = False
    df = stop_capture()
    st.session_state.captured_df = df

    if df.empty:
        st.error("No packets captured.")
    else:
        st.success(f"✅ Captured {df.shape[0]} packets.")

        # Threat scoring
        df["threat_score"] = 0
        if "flags" in df.columns:
            df.loc[df["flags"].str.contains("S", na=False), "threat_score"] += 2
        if not detect_blacklist(df).empty:
            df.loc[detect_blacklist(df).index, "threat_score"] += 10

        # ML Prediction
        if model_loaded:
            try:
                model = load_model()
                df = predict_live(model, df)
                if "predicted_label" in df.columns:
                    df.loc[df["predicted_label"] == 1, "threat_score"] += 5
            except:
                st.warning("⚠️ ML model not found. Skipping ML predictions.")

        # Filters
        if "protocol" in df.columns:
            protocol_filter = st.sidebar.multiselect(
                "Filter Protocols", options=df["protocol"].unique(), default=df["protocol"].unique()
            )
            filtered_df = df[df["protocol"].isin(protocol_filter)]
        else:
            filtered_df = df

        # Raw Data
        with st.expander("📄 Raw Packet Data"):
            st.dataframe(filtered_df)

        # Protocol Distribution
        st.subheader("📊 Protocol Distribution")
        fig1, _ = plot_protocol_distribution(filtered_df, show=False)
        if fig1:
            st.pyplot(fig1)

        # Packet Length
        st.subheader("📦 Packet Length Distribution")
        fig2, _ = plot_packet_length_distribution(filtered_df, show=False)
        if fig2:
            st.pyplot(fig2)

        # SYN Flood
        st.subheader("🚨 SYN Flood Detection")
        syn = detect_syn_flood(filtered_df)
        st.table(syn if hasattr(syn, "empty") and not syn.empty else pd.DataFrame({"Result": ["No SYN Flood detected"]}))

        # Port Scan
        st.subheader("🚨 Port Scan Detection")
        port_scan = detect_port_scan(filtered_df)
        st.table(port_scan if hasattr(port_scan, "empty") and not port_scan.empty else pd.DataFrame({"Result": ["No Port Scan detected"]}))

        # DDoS
        st.subheader("🚨 Possible DDoS Targets")
        ddos = detect_ddos(filtered_df)
        st.table(ddos if hasattr(ddos, "empty") and not ddos.empty else pd.DataFrame({"Result": ["No DDoS detected"]}))

        # Blacklist
        st.subheader("🚨 Blacklisted IPs")
        bl = detect_blacklist(filtered_df)
        st.table(bl if hasattr(bl, "empty") and not bl.empty else pd.DataFrame({"Result": ["No blacklisted IPs detected"]}))

        # Unusual Protocols
        st.subheader("🚨 Unusual Protocols")
        up = detect_unusual_protocol(filtered_df)
        st.table(up if hasattr(up, "empty") and not up.empty else pd.DataFrame({"Result": ["All protocols normal"]}))

        # Threat Scores
        st.subheader("🔥 Threat Scoring")
        high_threat = filtered_df[filtered_df["threat_score"] >= 5] if "threat_score" in filtered_df else pd.DataFrame()
        if not high_threat.empty:
            st.dataframe(high_threat.sort_values("threat_score", ascending=False))
        else:
            st.table(pd.DataFrame({"Result": ["No high threat packets detected"]}))

        # Export CSV
        st.download_button(
            "📄 Download Packets (CSV)",
                data=filtered_df.to_csv(index=False),
                file_name=f"captured_packets_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
        )

        # Export PDF
        st.download_button(
            "📄 Download Report (PDF)",
            data=generate_pdf_report(
                io.BytesIO(),
                filtered_df,
                {
                    "SYN Flood Detection": syn if hasattr(syn, "empty") and not syn.empty else "No SYN Flood detected",
                    "Port Scan Detection": port_scan if hasattr(port_scan, "empty") and not port_scan.empty else "No Port Scan detected",
                    "DDoS Detection": ddos if hasattr(ddos, "empty") and not ddos.empty else "No DDoS detected",
                    "Blacklisted IPs": bl if hasattr(bl, "empty") and not bl.empty else "No blacklisted IPs detected",
                    "Unusual Protocols": up if hasattr(up, "empty") and not up.empty else "All protocols normal",
                },
                {"Protocol Distribution": fig1, "Packet Length Distribution": fig2},
                high_threat,
                {
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "packet_count": filtered_df.shape[0],
                    "duration": "continuous",  # since not fixed
                    "interface": iface if iface else "default",
                }
            ),
            file_name=f"packet_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf"
        )
