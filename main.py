# analyze_rpl.py
# Combines PCAP + logs to produce full RPL metrics and multi-chart plot

import re
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import pyshark
import warnings

# Suppress warnings
warnings.filterwarnings("ignore")

# ========= Paths =========
BASE = Path(__file__).parent

def pick(name: str):
    p = BASE / name
    if p.exists():
        return p
    m = list(BASE.glob(name + '*'))
    if not m:
        raise FileNotFoundError(f"File not found: {name}* in {BASE}")
    return m[0]

PCAP_WITH_ATTACK    = pick('pacapwithattack')
PCAP_WITHOUT_ATTACK = pick('pacapwithoutattack')
LOG_WITH_ATTACK     = pick('withattackloglistener')
LOG_WITHOUT_ATTACK  = pick('withoutattackloglistener')

print("With attack PCAP  =>", PCAP_WITH_ATTACK)
print("Without attack PCAP =>", PCAP_WITHOUT_ATTACK)
print("With attack log   =>", LOG_WITH_ATTACK)
print("Without attack log =>", LOG_WITHOUT_ATTACK)

# ========= PCAP Parsing =========
def parse_pcap_metrics(pcap_path):
    send_times, recv_times = [], []
    sent, received = 0, 0

    if not Path(pcap_path).is_file():
        print(f"[Warning] PCAP not found: {pcap_path}")
        return {'PDR': 0.0, 'Average End-to-End Delay': 0.0, 'Throughput': 0.0}

    try:
        cap = pyshark.FileCapture(
            str(pcap_path),
            keep_packets=False,
            debug=True,
            custom_parameters=["-C", "rpl-test"]
        )
        
        for pkt in cap:
            try:
                t = float(pkt.sniff_timestamp)
                if hasattr(pkt, 'ipv6') or hasattr(pkt, 'icmpv6'):
                    sent += 1
                    send_times.append(t)
                    if hasattr(pkt, 'icmpv6'):
                        if int(getattr(pkt.icmpv6, 'type', 0)) in [129, 2, 155]:
                            received += 1
                            recv_times.append(t)
            except Exception:
                continue
        cap.close()
    except Exception as e:
        print(f"[Error] Failed to parse PCAP {pcap_path}: {str(e)[:200]}")
        return {'PDR': 0.0, 'Average End-to-End Delay': 0.0, 'Throughput': 0.0}

    pdr = (received / sent * 100) if sent > 0 else 0.0
    ae2ed = ((sum(recv_times) - sum(send_times[:len(recv_times)])) / len(recv_times)) * 1000 if recv_times else 0.0
    duration = max(recv_times + send_times) - min(recv_times + send_times) if recv_times and send_times else 1.0
    throughput = (received / duration) if duration > 0 else 0.0

    return {
        'PDR': pdr,
        'Average End-to-End Delay': ae2ed,
        'Throughput': throughput
    }

# ========= Log Parsing =========
ETX_PATTERN = re.compile(r'ETX\s*[:=]\s*(\d+\.?\d*)', re.I)
# Fixed RPL control pattern with proper parentheses
RPL_CTRL_PATTERN = re.compile(r'(\bRPL\s*(DIO|DAO|DIS)\b|\b(DIO|DAO|DIS)\b|icmpv6.*(rpl|155))', re.I)
ENERGY_PATTERN = re.compile(r'Total\s*energy:\s*(\d+\.?\d*)', re.I)

def parse_log_metrics(log_path):
    energy_score = 0.0
    etx_values = []
    ctrl_count = 0
    node_ids = set()
    
    try:
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                if 'Node id is set to' in line:
                    node_id = re.search(r'Node id is set to (\d+)', line)
                    if node_id:
                        node_ids.add(node_id.group(1))
                
                etx_match = ETX_PATTERN.search(line)
                if etx_match:
                    etx_values.append(float(etx_match.group(1)))
                
                if RPL_CTRL_PATTERN.search(line):
                    ctrl_count += 1
                    
                energy_match = ENERGY_PATTERN.search(line)
                if energy_match:
                    energy_score = float(energy_match.group(1))
                elif 'TX' in line and 'RX' in line:
                    energy_score += 1.0
    except Exception as e:
        print(f"[Error] Failed to parse log {log_path}: {e}")
        return {'Overhead Packets': 0.0, 'Energy Consumption': 0.0, 'Average ETX': 1.0}
    
    avg_etx = sum(etx_values)/len(etx_values) if etx_values else 1.0
    node_count = max(1, len(node_ids))
    normalized_ctrl = ctrl_count / node_count

    return {
        'Overhead Packets': float(normalized_ctrl),
        'Energy Consumption': float(energy_score),
        'Average ETX': float(avg_etx)
    }

# ========= Main Analysis =========
def main():
    try:
        m_with = parse_pcap_metrics(PCAP_WITH_ATTACK)
        m_with.update(parse_log_metrics(LOG_WITH_ATTACK))
        
        m_without = parse_pcap_metrics(PCAP_WITHOUT_ATTACK)
        m_without.update(parse_log_metrics(LOG_WITHOUT_ATTACK))

        metrics_order = [
            ('PDR', '%'),
            ('Average End-to-End Delay', 'ms'),
            ('Overhead Packets', 'count'),
            ('Energy Consumption', 'units'),
            ('Throughput', 'pkts/sec'),
            ('Average ETX', '')
        ]

        formatted_metrics = [f"{name} ({unit})" if unit else name for name, unit in metrics_order]
        metric_keys = [name for name, unit in metrics_order]

        df = pd.DataFrame({
            'Metric': formatted_metrics,
            'With Attack': [m_with.get(k, 0) for k in metric_keys],
            'Without Attack': [m_without.get(k, 0) for k in metric_keys]
        })

        pd.set_option('display.float_format', lambda v: '%.2f' % v)
        print("\n=== RPL Metrics ===")
        print(df.to_string(index=False))
        df.to_csv(BASE / 'metrics.csv', index=False)

        try:
            plt.style.use('seaborn-v0_8')
        except:
            plt.style.use('ggplot')

        fig, axes = plt.subplots(2, 3, figsize=(16, 10))
        axes = axes.flatten()

        for i, (metric, unit) in enumerate(metrics_order):
            ax = axes[i]
            values = [m_with.get(metric, 0), m_without.get(metric, 0)]
            colors = ['#FF6B6B', '#4ECDC4']
            
            bars = ax.bar(['With Attack', 'Without Attack'], values, color=colors)
            ax.set_title(f"{metric} ({unit})" if unit else metric, pad=10)
            ax.set_ylabel(unit if unit else 'Value', labelpad=5)
            
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                        f'{height:.2f}',
                        ha='center', va='bottom', fontsize=9)
            
            ax.yaxis.grid(True, linestyle='--', alpha=0.7)
            ax.set_axisbelow(True)

        plt.suptitle('RPL Performance Metrics Comparison', y=1.02, fontsize=14)
        plt.tight_layout()
        plt.savefig(BASE / 'metrics.png', dpi=200, bbox_inches='tight')
        plt.show()

    except Exception as e:
        print(f"[Critical Error] {str(e)}")

if __name__ == "__main__":
    main()