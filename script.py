import pandas as pd
import matplotlib.pyplot as plt
import re

# Parsing Functions

def parse_pacap(filename):
    rows = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 4:
                packet_id = int(parts[0])
                node_id = int(parts[1])

                # Handle cases like "1,26" or "1,26,5"
                split_vals = parts[2].split(",")
                try:
                    packet_type = int(split_vals[0])
                except ValueError:
                    packet_type = None
                try:
                    extra_val = int(split_vals[1]) if len(split_vals) > 1 else None
                except ValueError:
                    extra_val = None

                payload_hex = " ".join(parts[3:])
                payload_len = len(payload_hex.replace(" ", "")) // 2  # bytes
                rows.append({
                    "packet_id": packet_id,
                    "node_id": node_id,
                    "packet_type": packet_type,
                    "extra_val": extra_val,
                    "payload_hex": payload_hex,
                    "payload_len": payload_len
                })
    return pd.DataFrame(rows)


def parse_loglistener(filename):
    rows = []
    pattern = re.compile(r"(\d+:\d+\.\d+)\s+ID:(\d+)\s+(.*)")
    with open(filename, 'r') as f:
        for line in f:
            match = pattern.match(line.strip())
            if match:
                time_str = match.group(1)
                node_id = int(match.group(2))
                message = match.group(3)
                # Convert time mm:ss.mmm to seconds
                m, s = time_str.split(":")
                time_sec = int(m) * 60 + float(s)
                rows.append({
                    "time_sec": time_sec,
                    "node_id": node_id,
                    "message": message
                })
    return pd.DataFrame(rows)

# Load Data 
df_pacap_attack = parse_pacap("pacapwithattack")
df_pacap_noattack = parse_pacap("pacapwithoutattack")

df_log_attack = parse_loglistener("withattackloglistener.txt")
df_log_noattack = parse_loglistener("withoutattackloglistener.txt")

# Analysis 
# Packet count per node
packet_counts_attack   = df_pacap_attack.groupby("node_id").size()
packet_counts_noattack = df_pacap_noattack.groupby("node_id").size()

# Average payload length
avg_payload_attack = df_pacap_attack.groupby("node_id")["payload_len"].mean()
avg_payload_noattack = df_pacap_noattack.groupby("node_id")["payload_len"].mean()

# Events per second from logs
log_attack_timeline = df_log_attack.groupby(df_log_attack["time_sec"].astype(int)).size()
log_noattack_timeline = df_log_noattack.groupby(df_log_noattack["time_sec"].astype(int)).size()

# Visualization 
plt.figure(figsize=(12, 8))

# Bar chart: Packet counts
plt.subplot(3, 1, 1)
pd.DataFrame({
    "Attack": packet_counts_attack,
    "No Attack": packet_counts_noattack
}).plot(kind="bar", ax=plt.gca())
plt.title("Packets per Node (Attack vs No Attack)")
plt.ylabel("Packet Count")

# Histogram: Payload length
plt.subplot(3, 1, 2)
plt.hist(df_pacap_attack["payload_len"], bins=20, alpha=0.6, label="Attack")
plt.hist(df_pacap_noattack["payload_len"], bins=20, alpha=0.6, label="No Attack")
plt.title("Payload Length Distribution")
plt.xlabel("Payload Length (bytes)")
plt.ylabel("Frequency")
plt.legend()

# Timeline: Log event counts
plt.subplot(3, 1, 3)
plt.plot(log_attack_timeline.index, log_attack_timeline.values, label="Attack")
plt.plot(log_noattack_timeline.index, log_noattack_timeline.values, label="No Attack")
plt.title("Log Events per Second")
plt.xlabel("Time (s)")
plt.ylabel("Event Count")
plt.legend()

plt.tight_layout()
plt.show()
