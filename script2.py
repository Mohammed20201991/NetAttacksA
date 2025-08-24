import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

def parse_pacap(filename):
    """
    Parse PACAP text log into a DataFrame.
    Assumes lines are like: timestamp node_id packet_type payload_len payload_hex
    Handles 'packet_type' fields like '1,26'.
    """
    records = []
    with open(filename, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 5:
                continue
            ts_str = parts[0]
            node_id = int(parts[1])

            # Handle packet_type possibly having commas
            packet_type_parts = parts[2].split(",")
            try:
                packet_type_parts = [int(x) for x in packet_type_parts]
            except ValueError:
                continue  

            # Remove colon and convert to int
            payload_len_str = parts[3].rstrip(":")
            try:
                payload_len = int(payload_len_str)
            except ValueError:
                continue

            payload_hex = parts[4]
            timestamp = datetime.fromtimestamp(float(ts_str))

            records.append({
                "timestamp": timestamp,
                "node_id": node_id,
                "packet_type": packet_type_parts,
                "payload_len": payload_len,
                "payload_hex": payload_hex
            })

    return pd.DataFrame(records)

def detect_anomalies(df_attack, df_no_attack):
    anomalies = []

    #Node packet count spikes
    attack_counts = df_attack['node_id'].value_counts()
    threshold = attack_counts.mean() + 3 * attack_counts.std()
    spike_nodes = attack_counts[attack_counts > threshold].index.tolist()
    if spike_nodes:
        anomalies.append(f"Spike in packet count for nodes: {spike_nodes}")

    # Payload lengths unique to attack
    attack_lengths = set(df_attack['payload_len'])
    no_attack_lengths = set(df_no_attack['payload_len'])
    unique_lengths = attack_lengths - no_attack_lengths
    if unique_lengths:
        anomalies.append(f"Payload lengths unique to attack: {sorted(unique_lengths)}")

    # Unique payload hex patterns (first 4 bytes for example)
    attack_prefixes = {p[:8] for p in df_attack['payload_hex']}
    no_attack_prefixes = {p[:8] for p in df_no_attack['payload_hex']}
    unique_prefixes = attack_prefixes - no_attack_prefixes
    if unique_prefixes:
        anomalies.append(f"Payload prefixes unique to attack: {list(unique_prefixes)[:10]}")

    return anomalies

# Load Data 
df_pacap_attack = parse_pacap("pacapwithattack")
df_pacap_no_attack = parse_pacap("pacapwithoutattack")

# Visualization 
fig, axs = plt.subplots(3, 1, figsize=(10, 8))

# Packets per Node
attack_counts = df_pacap_attack['node_id'].value_counts().sort_index()
no_attack_counts = df_pacap_no_attack['node_id'].value_counts().sort_index()
axs[0].bar(attack_counts.index - 0.2, attack_counts, width=0.4, label="Attack")
axs[0].bar(no_attack_counts.index + 0.2, no_attack_counts, width=0.4, label="No Attack")
axs[0].set_title("Packets per Node (Attack vs No Attack)")
axs[0].set_xlabel("node_id")
axs[0].set_ylabel("Packet Count")
axs[0].legend()

# Payload Length Distribution
axs[1].hist(df_pacap_attack['payload_len'], bins=20, alpha=0.7, label="Attack")
axs[1].hist(df_pacap_no_attack['payload_len'], bins=20, alpha=0.7, label="No Attack")
axs[1].set_title("Payload Length Distribution")
axs[1].set_xlabel("Payload Length (bytes)")
axs[1].set_ylabel("Frequency")
axs[1].legend()

# Log Events per Second
attack_time_counts = df_pacap_attack['timestamp'].dt.floor('S').value_counts().sort_index()
no_attack_time_counts = df_pacap_no_attack['timestamp'].dt.floor('S').value_counts().sort_index()
axs[2].plot(attack_time_counts.index, attack_time_counts.values, label="Attack")
axs[2].plot(no_attack_time_counts.index, no_attack_time_counts.values, label="No Attack")
axs[2].set_title("Log Events per Second")
axs[2].set_xlabel("Time")
axs[2].set_ylabel("Event Count")
axs[2].legend()

plt.tight_layout()
plt.savefig("analysis_results.png", dpi=300)
plt.show()

# Anomaly Detection
anomalies = detect_anomalies(df_pacap_attack, df_pacap_no_attack)
print("\n=== Anomaly Report ===")
if anomalies:
    for a in anomalies:
        print("-", a)
else:
    print("No anomalies detected.")