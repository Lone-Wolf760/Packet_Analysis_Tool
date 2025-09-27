import matplotlib.pyplot as plt

def plot_protocol_distribution(df, show=True):
    if "protocol" not in df.columns or df["protocol"].dropna().empty:
        print("⚠️ No protocol info available.")
        return None, None

    fig, ax = plt.subplots()
    df["protocol"].value_counts().plot(kind="bar", color="skyblue", ax=ax, edgecolor="black")
    ax.set_title("Protocol Distribution")
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Count")

    if show:
        plt.show()
    return fig, ax

def plot_packet_length_distribution(df, show=True):
    if "length" not in df.columns:
        print("⚠️ No packet length info available.")
        return None, None

    fig, ax = plt.subplots()
    df["length"].plot(kind="hist", bins=20, ax=ax, color="lightgreen", edgecolor="black")
    ax.set_title("Packet Length Distribution")
    ax.set_xlabel("Packet Size (bytes)")
    ax.set_ylabel("Frequency")

    if show:
        plt.show()
    return fig, ax
