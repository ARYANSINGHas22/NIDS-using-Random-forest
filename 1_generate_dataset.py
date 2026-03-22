"""
NIDS Dataset Generator
======================
Generates a synthetic but realistic labeled network traffic dataset.
Each row = one 5-second capture window with 13 features + 1 label.

Labels:
  0 = Normal
  1 = Suspicious / Attack

Attack types simulated:
  - Port Scan       : many src IPs, small packets, high ICMP
  - DDoS            : massive packet count, high incoming ratio
  - Brute Force     : many connections to 1-2 dst IPs, small pkt size
  - Data Exfiltration: high outgoing ratio, large avg packet size
  - UDP Flood       : very high UDP ratio, moderate packet count
"""

import numpy as np
import pandas as pd
from pathlib import Path

np.random.seed(42)
OUTDIR = Path("data")
OUTDIR.mkdir(exist_ok=True)

# ─── helpers ───────────────────────────────────────────────────────────────
def clip(x, lo, hi): return max(lo, min(hi, x))
def rand(lo, hi):    return np.random.uniform(lo, hi)
def randi(lo, hi):   return np.random.randint(lo, hi+1)

# ─── traffic generators ────────────────────────────────────────────────────
def normal_window():
    pkt_count       = randi(30, 200)
    avg_pkt_size    = rand(300, 1400)
    tcp_ratio       = rand(0.50, 0.85)
    udp_ratio       = rand(0.05, 0.30)
    icmp_ratio      = rand(0.01, 0.08)
    other_ratio     = clip(1 - tcp_ratio - udp_ratio - icmp_ratio, 0, 1)
    unique_src_ips  = randi(2, 20)
    unique_dst_ips  = randi(2, 18)
    in_ratio        = rand(0.30, 0.70)
    out_ratio       = 1 - in_ratio
    syn_flag_ratio  = rand(0.01, 0.10)
    pkt_rate        = pkt_count / 5.0
    byte_rate       = pkt_rate * avg_pkt_size
    label = 0
    return locals()

def port_scan_window():
    pkt_count       = randi(200, 800)
    avg_pkt_size    = rand(40, 120)       # tiny probe packets
    tcp_ratio       = rand(0.30, 0.60)
    udp_ratio       = rand(0.10, 0.25)
    icmp_ratio      = rand(0.20, 0.50)    # ping sweeps
    other_ratio     = clip(1 - tcp_ratio - udp_ratio - icmp_ratio, 0, 1)
    unique_src_ips  = randi(1, 5)         # few attackers
    unique_dst_ips  = randi(20, 250)      # scanning many ports/IPs
    in_ratio        = rand(0.60, 0.90)
    out_ratio       = 1 - in_ratio
    syn_flag_ratio  = rand(0.40, 0.90)    # SYN packets dominate
    pkt_rate        = pkt_count / 5.0
    byte_rate       = pkt_rate * avg_pkt_size
    label = 1
    return locals()

def ddos_window():
    pkt_count       = randi(600, 2000)
    avg_pkt_size    = rand(40, 300)
    tcp_ratio       = rand(0.10, 0.40)
    udp_ratio       = rand(0.30, 0.70)
    icmp_ratio      = rand(0.10, 0.40)
    other_ratio     = clip(1 - tcp_ratio - udp_ratio - icmp_ratio, 0, 1)
    unique_src_ips  = randi(50, 400)      # botnet → many sources
    unique_dst_ips  = randi(1, 4)         # single target
    in_ratio        = rand(0.80, 1.00)
    out_ratio       = 1 - in_ratio
    syn_flag_ratio  = rand(0.05, 0.30)
    pkt_rate        = pkt_count / 5.0
    byte_rate       = pkt_rate * avg_pkt_size
    label = 1
    return locals()

def brute_force_window():
    pkt_count       = randi(150, 600)
    avg_pkt_size    = rand(60, 200)
    tcp_ratio       = rand(0.70, 0.95)    # mostly TCP (SSH/FTP/HTTP)
    udp_ratio       = rand(0.01, 0.10)
    icmp_ratio      = rand(0.00, 0.05)
    other_ratio     = clip(1 - tcp_ratio - udp_ratio - icmp_ratio, 0, 1)
    unique_src_ips  = randi(1, 8)
    unique_dst_ips  = randi(1, 3)         # hammering 1-3 services
    in_ratio        = rand(0.40, 0.65)
    out_ratio       = 1 - in_ratio
    syn_flag_ratio  = rand(0.20, 0.60)
    pkt_rate        = pkt_count / 5.0
    byte_rate       = pkt_rate * avg_pkt_size
    label = 1
    return locals()

def exfiltration_window():
    pkt_count       = randi(80, 400)
    avg_pkt_size    = rand(800, 1500)     # large payloads going OUT
    tcp_ratio       = rand(0.55, 0.85)
    udp_ratio       = rand(0.05, 0.30)
    icmp_ratio      = rand(0.00, 0.05)
    other_ratio     = clip(1 - tcp_ratio - udp_ratio - icmp_ratio, 0, 1)
    unique_src_ips  = randi(1, 5)
    unique_dst_ips  = randi(1, 6)
    in_ratio        = rand(0.05, 0.30)    # mostly outgoing
    out_ratio       = 1 - in_ratio
    syn_flag_ratio  = rand(0.01, 0.08)
    pkt_rate        = pkt_count / 5.0
    byte_rate       = pkt_rate * avg_pkt_size
    label = 1
    return locals()

def udp_flood_window():
    pkt_count       = randi(400, 1200)
    avg_pkt_size    = rand(50, 400)
    tcp_ratio       = rand(0.03, 0.15)
    udp_ratio       = rand(0.70, 0.95)    # dominant UDP
    icmp_ratio      = rand(0.00, 0.05)
    other_ratio     = clip(1 - tcp_ratio - udp_ratio - icmp_ratio, 0, 1)
    unique_src_ips  = randi(10, 200)
    unique_dst_ips  = randi(1, 5)
    in_ratio        = rand(0.75, 0.98)
    out_ratio       = 1 - in_ratio
    syn_flag_ratio  = rand(0.00, 0.03)
    pkt_rate        = pkt_count / 5.0
    byte_rate       = pkt_rate * avg_pkt_size
    label = 1
    return locals()

# ─── build dataset ─────────────────────────────────────────────────────────
GENERATORS = [
    (normal_window,      3000),   # 60 % normal
    (port_scan_window,    400),
    (ddos_window,         400),
    (brute_force_window,  400),
    (exfiltration_window, 400),
    (udp_flood_window,    400),
]

COLS = [
    "pkt_count","avg_pkt_size","tcp_ratio","udp_ratio","icmp_ratio",
    "other_ratio","unique_src_ips","unique_dst_ips","in_ratio","out_ratio",
    "syn_flag_ratio","pkt_rate","byte_rate","label"
]

rows = []
for fn, n in GENERATORS:
    for _ in range(n):
        w = fn()
        rows.append([w[c] for c in COLS])

df = pd.DataFrame(rows, columns=COLS).sample(frac=1, random_state=42).reset_index(drop=True)

# Add noise to all numeric columns except label
numeric_cols = COLS[:-1]
noise = np.random.normal(0, 0.01, size=(len(df), len(numeric_cols)))
df[numeric_cols] = (df[numeric_cols] + noise).clip(lower=0)

df.to_csv(OUTDIR / "nids_dataset.csv", index=False)
print(f"✓ Dataset saved → data/nids_dataset.csv")
print(f"  Total rows : {len(df)}")
print(f"  Normal (0) : {(df.label==0).sum()}  ({(df.label==0).mean()*100:.1f}%)")
print(f"  Suspect(1) : {(df.label==1).sum()}  ({(df.label==1).mean()*100:.1f}%)")
print(f"\nColumn preview:\n{df.describe().round(2)}")