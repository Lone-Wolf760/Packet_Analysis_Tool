from blacklist import check_blacklist

def detect_syn_flood(df, threshold=100):
    if "flags" not in df.columns:
        return []
    syn_packets = df[df["flags"].str.contains("S", na=False)]
    suspicious = syn_packets["src"].value_counts()
    return suspicious[suspicious > threshold]

def detect_port_scan(df, port_threshold=20):
    if "dst_port" not in df.columns:
        return []
    port_counts = df.groupby("src")["dst_port"].nunique()
    return port_counts[port_counts > port_threshold]

def detect_ddos(df, threshold=50):
    if "dst" not in df.columns:
        return []
    dst_counts = df["dst"].value_counts()
    return dst_counts[dst_counts > threshold]

def detect_blacklist(df):
    if "src" not in df.columns:
        return []
    return df[df["src"].apply(check_blacklist)]

def detect_unusual_protocol(df, allowed_protocols=["TCP", "UDP", "ICMP"]):
    if "protocol" not in df.columns:
        return []
    return df[~df["protocol"].isin(allowed_protocols)]

def protocol_distribution(df):
    if "protocol" not in df.columns:
        return {}
    return df["protocol"].value_counts()
