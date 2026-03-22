"""
Run this AS ADMINISTRATOR in PowerShell:
    python debug_capture.py

It will tell you exactly what Scapy can and cannot see.
"""
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, get_if_list
import threading, time, socket

WIFI_IFACE     = r"\Device\NPF_{AD647D65-0BFC-4B60-AD4D-95EC40EB0738}"
LOOPBACK_IFACE = r"\Device\NPF_Loopback"

captured = []

def on_packet(pkt):
    if pkt.haslayer(IP):
        ip = pkt[IP]
        captured.append({
            "src"  : ip.src,
            "dst"  : ip.dst,
            "size" : len(pkt),
            "proto": "TCP" if pkt.haslayer(TCP) else
                     "UDP" if pkt.haslayer(UDP) else
                     "ICMP" if pkt.haslayer(ICMP) else "OTHER"
        })

print("=" * 55)
print("  NIDS Debug — Packet Capture Test")
print("=" * 55)

# ── Test 1: Can we sniff Wi-Fi? ─────────────────────────────────────────
print("\n[TEST 1] Sniffing Wi-Fi for 5 seconds...")
print(f"  Interface: {WIFI_IFACE}")
captured.clear()
try:
    sniff(iface=WIFI_IFACE, prn=on_packet, store=False,
          filter="ip", timeout=5)
    print(f"  Result: captured {len(captured)} packets")
    if captured:
        print("  Sample packets:")
        for p in captured[:3]:
            print(f"    {p['src']:20s} → {p['dst']:20s}  {p['proto']}  {p['size']}B")
    else:
        print("  WARNING: Zero packets captured on Wi-Fi!")
        print("  → Try opening a browser or running ping while this runs")
except Exception as e:
    print(f"  ERROR: {e}")

# ── Test 2: Can we sniff Loopback? ──────────────────────────────────────
print("\n[TEST 2] Sniffing Loopback for 3 seconds...")
captured.clear()
try:
    sniff(iface=LOOPBACK_IFACE, prn=on_packet, store=False,
          filter="ip", timeout=3)
    print(f"  Result: captured {len(captured)} packets on loopback")
except Exception as e:
    print(f"  ERROR on loopback: {e}")

# ── Test 3: Send a test packet to ourselves and sniff it ─────────────────
print("\n[TEST 3] Self-ping test (send + capture)...")
from scapy.all import send, ICMP as ScapyICMP, IP as ScapyIP
my_ip = "192.168.0.220"
test_captured = []

def sniff_test(iface):
    sniff(iface=iface, prn=lambda p: test_captured.append(p),
          store=False, filter="icmp", timeout=4)

# start sniffer
t = threading.Thread(target=sniff_test, args=(WIFI_IFACE,), daemon=True)
t.start()
time.sleep(0.5)

# send test packet
try:
    send(ScapyIP(dst=my_ip)/ScapyICMP(), verbose=False)
    print(f"  Sent ICMP packet to {my_ip}")
except Exception as e:
    print(f"  Send error: {e}")

t.join(timeout=4)
print(f"  Captured {len(test_captured)} ICMP packets")
if test_captured:
    print("  SUCCESS — Scapy can see its own packets on Wi-Fi!")
else:
    print("  PROBLEM — Scapy cannot see self-sent packets on Wi-Fi")
    print("  This is why the attack simulator does not show on dashboard")
    print("\n  FIX: The attack simulator must use a different method on Windows")

# ── Test 4: Check if running as admin ────────────────────────────────────
print("\n[TEST 4] Checking admin rights...")
import ctypes
try:
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    print(f"  Running as Administrator: {'YES' if is_admin else 'NO — THIS IS THE PROBLEM'}")
    if not is_admin:
        print("  Right-click PowerShell → Run as Administrator")
except Exception:
    print("  Could not check admin status (non-Windows?)")

print("\n" + "=" * 55)
print("  Share the output above so we can diagnose the issue")
print("=" * 55)