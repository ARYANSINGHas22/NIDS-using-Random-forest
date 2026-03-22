"""
NIDS Attack Simulator — Windows Compatible
==========================================
Uses real socket connections instead of raw Scapy packets.
This guarantees traffic appears on your Wi-Fi interface
and is captured by the Flask server sniffer.

Run in a SECOND terminal (no admin needed for this file):
    python 5_attack_simulator.py
"""

import socket, threading, time, random, sys
from datetime import datetime

TARGET_IP   = "192.168.0.220"   # your Wi-Fi IP
FLASK_PORT  = 5000

def ts():
    return datetime.now().strftime("%H:%M:%S")

def progress(label, done, total):
    pct = int(done / total * 30)
    bar = "█" * pct + "░" * (30 - pct)
    print(f"\r  [{bar}] {done}/{total}  {label}", end="", flush=True)

# ══════════════════════════════════════════════════════════════
#  ATTACK FUNCTIONS — all use real sockets
# ══════════════════════════════════════════════════════════════

def tcp_syn_flood(n=300):
    """
    Opens many rapid TCP connections to Flask server.
    Creates high pkt_count + high syn_flag_ratio → SYN_FLOOD rule.
    """
    print(f"\n[{ts()}] ⚡ TCP CONNECTION FLOOD → {TARGET_IP}:{FLASK_PORT}")
    print(f"  Firing {n} rapid TCP connections...\n")
    success = 0
    for i in range(n):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((TARGET_IP, FLASK_PORT))
            s.close()
            success += 1
        except Exception:
            pass
        if i % 30 == 0:
            progress("TCP FLOOD", i+1, n)
        time.sleep(0.005)
    print(f"\n[{ts()}] ✓ Done — {success} connections made\n")


def udp_flood(n=500):
    """
    Blasts UDP packets to random ports.
    Drives udp_ratio > 0.60 → UDP_FLOOD rule triggered.
    """
    print(f"\n[{ts()}] 🌊 UDP FLOOD → {TARGET_IP}")
    print(f"  Sending {n} UDP packets to random ports...\n")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(n):
        try:
            port = random.randint(1024, 65535)
            data = random.randbytes(random.randint(8, 512))
            s.sendto(data, (TARGET_IP, port))
        except Exception:
            pass
        if i % 50 == 0:
            progress("UDP FLOOD", i+1, n)
        time.sleep(0.002)
    s.close()
    print(f"\n[{ts()}] ✓ UDP flood done — {n} packets\n")


def icmp_flood(n=200):
    """
    Sends ICMP echo (ping) packets using os.system ping.
    Drives icmp_ratio up → ICMP_FLOOD rule triggered.
    """
    import subprocess
    print(f"\n[{ts()}] 💥 ICMP FLOOD (PING STORM) → {TARGET_IP}")
    print(f"  Sending {n} rapid pings...\n")
    threads = []
    count   = [0]
    lock    = threading.Lock()

    def ping_worker(num):
        for _ in range(num):
            try:
                subprocess.run(
                    ["ping", "-n", "1", "-w", "100", TARGET_IP],
                    capture_output=True, timeout=1
                )
                with lock:
                    count[0] += 1
            except Exception:
                pass

    # 10 threads each sending n/10 pings
    per_thread = n // 10
    for _ in range(10):
        t = threading.Thread(target=ping_worker, args=(per_thread,), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()
    print(f"[{ts()}] ✓ ICMP flood done — {count[0]} pings sent\n")


def http_flood(n=400):
    """
    Sends many HTTP GET requests to Flask server.
    Creates high pkt_count + many connections → HIGH_PKT_RATE rule.
    """
    print(f"\n[{ts()}] 🔥 HTTP REQUEST FLOOD → {TARGET_IP}:{FLASK_PORT}")
    print(f"  Sending {n} HTTP requests...\n")
    success = 0
    endpoints = ["/", "/api/window", "/api/history", "/api/summary"]

    def send_request(ep):
        nonlocal success
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((TARGET_IP, FLASK_PORT))
            req = f"GET {ep} HTTP/1.0\r\nHost: {TARGET_IP}\r\n\r\n"
            s.send(req.encode())
            s.recv(128)
            s.close()
            success += 1
        except Exception:
            pass

    threads = []
    for i in range(n):
        ep = random.choice(endpoints)
        t  = threading.Thread(target=send_request, args=(ep,), daemon=True)
        t.start()
        threads.append(t)
        if i % 40 == 0:
            progress("HTTP FLOOD", i+1, n)
        time.sleep(0.003)

    for t in threads:
        t.join(timeout=2)
    print(f"\n[{ts()}] ✓ HTTP flood done — {success} requests\n")


def port_scan(ports=200):
    """
    Scans many TCP ports on target.
    Creates many unique connections → high pkt_count.
    """
    print(f"\n[{ts()}] 🔍 PORT SCAN → {TARGET_IP}")
    print(f"  Scanning {ports} ports...\n")
    port_list = random.sample(range(1, 65535), ports)
    open_ports = []
    for i, port in enumerate(port_list):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            result = s.connect_ex((TARGET_IP, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
        if i % 20 == 0:
            progress("PORT SCAN", i+1, ports)
        time.sleep(0.003)
    print(f"\n[{ts()}] ✓ Port scan done — found {len(open_ports)} open ports: {open_ports}\n")


def brute_force(n=300):
    """
    Rapid repeated connections to port 5000 (Flask) simulating brute force.
    High TCP connection rate → triggers HIGH_PKT_RATE.
    """
    print(f"\n[{ts()}] 🔑 BRUTE FORCE SIM → {TARGET_IP}:{FLASK_PORT}")
    print(f"  Hammering {n} rapid connections to Flask port...\n")
    for i in range(n):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect_ex((TARGET_IP, FLASK_PORT))
            # Send fake auth attempt
            s.send(b"POST /login HTTP/1.0\r\nContent-Length: 30\r\n\r\nuser=admin&pass=password123")
            s.close()
        except Exception:
            pass
        if i % 30 == 0:
            progress("BRUTE FORCE", i+1, n)
        time.sleep(0.005)
    print(f"\n[{ts()}] ✓ Brute force done — {n} attempts\n")


def data_exfil(n=150):
    """
    Sends large outbound data bursts simulating data exfiltration.
    High out_ratio + large packet size → EXFILTRATION rule.
    """
    print(f"\n[{ts()}] 📤 DATA EXFILTRATION SIM → {TARGET_IP}:{FLASK_PORT}")
    print(f"  Sending {n} large data payloads...\n")
    for i in range(n):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((TARGET_IP, FLASK_PORT))
            # Send large payload
            payload = b"X" * random.randint(800, 1400)
            req = (f"POST /upload HTTP/1.0\r\n"
                   f"Content-Length: {len(payload)}\r\n\r\n").encode() + payload
            s.send(req)
            s.close()
        except Exception:
            pass
        if i % 15 == 0:
            progress("EXFIL", i+1, n)
        time.sleep(0.01)
    print(f"\n[{ts()}] ✓ Exfiltration sim done — {n} large packets\n")


def full_demo():
    """
    Full demo sequence — runs all attacks with pauses.
    Perfect for viva presentation.
    Watch the dashboard go red!
    """
    print("\n" + "="*55)
    print("  FULL DEMO SEQUENCE — watch your dashboard!")
    print("  Each attack lasts ~10s then traffic returns to normal")
    print("="*55 + "\n")

    sequence = [
        ("Normal window pause",   None,        6),
        ("HTTP Flood",            http_flood,  0),
        ("Normal window pause",   None,        6),
        ("UDP Flood",             udp_flood,   0),
        ("Normal window pause",   None,        6),
        ("TCP Connection Flood",  tcp_syn_flood,0),
        ("Normal window pause",   None,        6),
        ("Port Scan",             port_scan,   0),
        ("Normal window pause",   None,        6),
        ("Brute Force",           brute_force, 0),
        ("Normal window pause",   None,        6),
        ("Data Exfiltration",     data_exfil,  0),
        ("Normal window pause",   None,        6),
        ("ICMP Flood",            icmp_flood,  0),
        ("Demo complete!",        None,        0),
    ]

    for label, fn, pause in sequence:
        print(f"\n  ▶  {label}")
        if fn:
            fn()
        if pause:
            print(f"     waiting {pause}s...")
            time.sleep(pause)

    print("\n✓ Full demo sequence complete!")


# ══════════════════════════════════════════════════════════════
#  MENU
# ══════════════════════════════════════════════════════════════
MENU = """
╔══════════════════════════════════════════════════════╗
║        NIDS Attack Simulator — Windows Edition       ║
║     Uses real sockets — no Npcap/admin needed        ║
╠══════════════════════════════════════════════════════╣
║  1. HTTP Request Flood    (400 rapid HTTP requests)  ║
║  2. UDP Flood             (500 UDP packets)          ║
║  3. TCP Connection Flood  (300 TCP connections)      ║
║  4. Port Scan             (200 ports)                ║
║  5. Brute Force Sim       (300 connection attempts)  ║
║  6. Data Exfiltration     (150 large payloads)       ║
║  7. ICMP Flood            (200 pings)                ║
║  8. 🎬 FULL DEMO SEQUENCE  (all attacks)             ║
║  0. Exit                                             ║
╚══════════════════════════════════════════════════════╝
Target: 192.168.0.220 (your Wi-Fi IP)
"""

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  NIDS Attack Simulator")
    print(f"  Target IP : {TARGET_IP}")
    print(f"  Flask port: {FLASK_PORT}")
    print("  Make sure 6_flask_server.py is running first!")
    print("="*55)

    dispatch = {
        "1": http_flood,
        "2": udp_flood,
        "3": tcp_syn_flood,
        "4": port_scan,
        "5": brute_force,
        "6": data_exfil,
        "7": icmp_flood,
        "8": full_demo,
    }

    while True:
        print(MENU)
        choice = input("  Select attack [0-8]: ").strip()
        if choice == "0":
            print("Exiting.")
            break
        elif choice in dispatch:
            dispatch[choice]()
        else:
            print("Invalid choice.")