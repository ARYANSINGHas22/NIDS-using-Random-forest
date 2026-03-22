from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import threading, time, joblib, numpy as np
import socket, platform, random
from pathlib import Path
from datetime import datetime
from collections import deque, defaultdict

# ── Config ────────────────────────────────────────────────────
CAPTURE_IFACE  = r"\Device\NPF_{AD647D65-0BFC-4B60-AD4D-95EC40EB0738}"
LOOPBACK_IFACE = r"\Device\NPF_Loopback"
WINDOW_SECONDS = 5

# ── Detect local IP ───────────────────────────────────────────
try:
    _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _s.connect(("8.8.8.8", 80))
    MY_IP = _s.getsockname()[0]
    _s.close()
except Exception:
    MY_IP = "127.0.0.1"

# ── Load Scapy ────────────────────────────────────────────────
SCAPY_OK = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf as sc
    sc.verb = 0
    SCAPY_OK = True
    print("OK  Scapy loaded")
except Exception as e:
    print("WARN Scapy unavailable - simulation mode")

# ── Load Model ────────────────────────────────────────────────
MODEL_DIR = Path("models")
try:
    rf       = joblib.load(MODEL_DIR / "rf_nids_model.pkl")
    scaler   = joblib.load(MODEL_DIR / "scaler.pkl")
    FEATURES = joblib.load(MODEL_DIR / "feature_names.pkl")
    print("OK  Model loaded")
except Exception as e:
    print("ERROR Cannot load model:", e)
    print("Run 1_generate_dataset.py then 2_train_model.py first")
    import sys; sys.exit(1)

# ── Shared state ──────────────────────────────────────────────
pkt_buffer = []
buf_lock   = threading.Lock()
history    = deque(maxlen=50)
summary    = {"total_pkts": 0, "normal": 0, "suspicious": 0,
              "alerts": 0, "windows": 0}
latest     = {}
sim_streak = [0]

app = Flask(__name__, static_folder=".")
CORS(app)

# ── Packet callback (real capture) ────────────────────────────
def on_packet(pkt):
    try:
        if not pkt.haslayer(IP):
            return
        layer = pkt[IP]
        if pkt.haslayer(TCP):
            proto = "TCP"
            syn   = bool(pkt[TCP].flags & 0x02)
        elif pkt.haslayer(UDP):
            proto = "UDP"
            syn   = False
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            syn   = False
        else:
            proto = "OTHER"
            syn   = False
        with buf_lock:
            pkt_buffer.append({
                "src":   layer.src,
                "dst":   layer.dst,
                "size":  len(pkt),
                "proto": proto,
                "dir":   "out" if layer.src == MY_IP else "in",
                "syn":   syn,
            })
    except Exception:
        pass

# ── Simulation (matches training data distributions exactly) ──
def make_sim_packets(attack=False):
    if attack:
        # matches suspicious rows in training data
        n     = random.randint(500, 1200)
        pool  = ["TCP"]*2 + ["UDP"]*5 + ["ICMP"]*3
        sizes = (40, 200)
        n_src = random.randint(50, 300)
        n_dst = random.randint(1, 5)
        in_r  = 0.80
    else:
        # matches normal rows in training data exactly
        n     = random.randint(30, 200)
        pool  = ["TCP"]*7 + ["UDP"]*2 + ["ICMP"]*1
        sizes = (300, 1400)
        n_src = random.randint(2, 20)
        n_dst = random.randint(2, 18)
        in_r  = 0.50

    src_pool = ["192.168.0.{}".format(i) for i in range(1, n_src+1)]
    dst_pool = ["10.0.0.{}".format(i)    for i in range(1, n_dst+1)]
    packets  = []
    for _ in range(n):
        pr  = random.choice(pool)
        dir_ = "in" if random.random() < in_r else "out"
        packets.append({
            "src":   random.choice(src_pool),
            "dst":   random.choice(dst_pool),
            "size":  random.randint(*sizes),
            "proto": pr,
            "dir":   dir_,
            "syn":   pr == "TCP" and random.random() < (0.6 if attack else 0.04),
        })
    return packets

# ── Feature extraction ────────────────────────────────────────
def get_features(packets):
    n = len(packets)
    if n < 3:
        return None
    sizes = [p["size"]  for p in packets]
    pros  = [p["proto"] for p in packets]
    srcs  = [p["src"]   for p in packets]
    dsts  = [p["dst"]   for p in packets]
    dirs  = [p["dir"]   for p in packets]
    tcp   = pros.count("TCP")
    udp   = pros.count("UDP")
    icmp  = pros.count("ICMP")
    inc   = dirs.count("in")
    syn   = sum(1 for p in packets if p.get("syn"))
    return {
        "pkt_count":      n,
        "avg_pkt_size":   float(np.mean(sizes)),
        "tcp_ratio":      tcp  / n,
        "udp_ratio":      udp  / n,
        "icmp_ratio":     icmp / n,
        "other_ratio":    max(0, (n - tcp - udp - icmp) / n),
        "unique_src_ips": len(set(srcs)),
        "unique_dst_ips": len(set(dsts)),
        "in_ratio":       inc  / n,
        "out_ratio":      (n - inc) / n,
        "syn_flag_ratio": syn  / n,
        "pkt_rate":       n    / WINDOW_SECONDS,
        "byte_rate":      sum(sizes) / WINDOW_SECONDS,
    }

# ── Rule engine ───────────────────────────────────────────────
def check_rules(f):
    rules = []
    if f["pkt_count"] > 1000: rules.append("HIGH_PKT_RATE")
    if f["unique_src_ips"] > 150: rules.append("MANY_SRC_IPS")
    if f["icmp_ratio"]     > 0.30: rules.append("ICMP_FLOOD")
    if f["udp_ratio"]      > 0.60: rules.append("UDP_FLOOD")
    if f["syn_flag_ratio"] > 0.40: rules.append("SYN_FLOOD")
    if f["out_ratio"] > 0.80 and f["avg_pkt_size"] > 900:
        rules.append("EXFILTRATION")
    return rules

# ── Classify one window ───────────────────────────────────────
def classify_window(packets):
    feat = get_features(packets)
    if feat is None:
        return None
    vec      = np.array([[feat[k] for k in FEATURES]])
    vec_s    = scaler.transform(vec)
    ml_pred  = int(rf.predict(vec_s)[0])
    ml_proba = rf.predict_proba(vec_s)[0]
    rules    = check_rules(feat)
    final    = 1 if (ml_pred == 1 or len(rules) > 0) else 0
    src_cnt  = defaultdict(int)
    for p in packets:
        src_cnt[p["src"]] += 1
    top_ips = sorted(src_cnt.items(), key=lambda x: -x[1])[:5]
    return {
        "timestamp":     datetime.now().strftime("%H:%M:%S"),
        "pkt_count":     feat["pkt_count"],
        "ml_label":      ml_pred,
        "ml_confidence": round(float(max(ml_proba)), 4),
        "rules_fired":   rules,
        "final_label":   final,
        "verdict":       "Suspicious" if final == 1 else "Normal",
        "features":      {k: round(v, 4) for k, v in feat.items()},
        "proba_normal":  round(float(ml_proba[0]), 4),
        "proba_attack":  round(float(ml_proba[1]), 4),
        "top_src_ips":   [{"ip": ip, "pkts": c} for ip, c in top_ips],
    }

# ── Background window loop ────────────────────────────────────
def window_loop():
    global latest
    while True:
        time.sleep(WINDOW_SECONDS)

        if SCAPY_OK:
            with buf_lock:
                win_pkts = pkt_buffer.copy()
                pkt_buffer.clear()
            if len(win_pkts) < 3:
                win_pkts = make_sim_packets(attack=False)
                src_tag  = "sim-normal"
            else:
                src_tag  = "real"
        else:
            if sim_streak[0] == 0 and random.random() < 0.15:
                sim_streak[0] = random.randint(2, 3)
            is_atk = sim_streak[0] > 0
            if sim_streak[0] > 0:
                sim_streak[0] -= 1
            win_pkts = make_sim_packets(attack=is_atk)
            src_tag  = "sim-attack" if is_atk else "sim-normal"

        res = classify_window(win_pkts)
        if res is None:
            continue

        summary["windows"]    += 1
        summary["total_pkts"] += res["pkt_count"]
        if res["final_label"] == 0:
            summary["normal"] += 1
        else:
            summary["suspicious"] += 1
            summary["alerts"]     += 1

        res["summary"]    = dict(summary)
        res["window_num"] = summary["windows"]
        res["source"]     = src_tag
        latest = res
        history.appendleft(res)

        verdict  = "SUSPICIOUS" if res["final_label"] == 1 else "Normal"
        t_str    = res["timestamp"]
        win_num  = summary["windows"]
        pkt_num  = res["pkt_count"]
        conf_val = res["ml_confidence"]
        print("[{}] Win#{:04d}  {:10s}  pkts={:5d}  conf={:.2f}  src={}".format(
            t_str, win_num, verdict, pkt_num, conf_val, src_tag))

# ── Flask routes ──────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(".", "nids_dashboard_live.html")

@app.route("/api/window")
def api_window():
    return jsonify(latest if latest else {"status": "waiting"})

@app.route("/api/history")
def api_history():
    return jsonify(list(history))

@app.route("/api/summary")
def api_summary():
    return jsonify(summary)

# ── Startup ───────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  NIDS SENTINEL — Flask Server")
    print("  OS       :", platform.system())
    print("  Local IP :", MY_IP)
    if SCAPY_OK:
        t1 = threading.Thread(
            target=lambda: sniff(
                prn=on_packet, store=False,
                filter="ip", iface=CAPTURE_IFACE),
            daemon=True)
        t1.start()
        t2 = threading.Thread(
            target=lambda: sniff(
                prn=on_packet, store=False,
                filter="ip", iface=LOOPBACK_IFACE),
            daemon=True)
        t2.start()
        print("  Capture  : REAL (Wi-Fi + Loopback)")
    else:
        print("  Capture  : SIMULATION mode")
    threading.Thread(target=window_loop, daemon=True).start()
    print("  Window   :", WINDOW_SECONDS, "seconds")
    print("  Dashboard: http://localhost:5000")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)