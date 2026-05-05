from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, srp
import threading
import time
from collections import defaultdict
from datetime import datetime
import subprocess
import socket

app = Flask(__name__)

# ---------------- CONFIG ----------------
TIME_WINDOW = 5
SCAN_THRESHOLD = 10
FLOOD_THRESHOLD = 100
ICMP_THRESHOLD = 20

local_ip = "192.168.1.10"   # ⚠️ CHANGE YOUR IP

# ---------------- STATE ----------------
state_lock = threading.Lock()
traffic_data = defaultdict(list)
icmp_data = defaultdict(list)
udp_data = defaultdict(list)

detected_attackers = {}
alerts = []

# ---------------- NETWORK ALERT ----------------
def send_network_alert(msg):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(msg.encode(), ("255.255.255.255", 9999))
        s.close()
    except:
        pass

# ---------------- BLOCK ----------------
def block_ip(ip):
    try:
        subprocess.run([
            "netsh","advfirewall","firewall",
            "add","rule",
            f"name=Block_{ip}",
            "dir=in","action=block",
            f"remoteip={ip}"
        ])
        print("BLOCKED:", ip)
    except:
        pass

def unblock_ip(ip):
    subprocess.run([
        "netsh","advfirewall","firewall",
        "delete","rule",
        f"name=Block_{ip}"
    ])

# ---------------- ALERT ----------------
def add_alert(ip, typ, detail):
    now = datetime.now().strftime("%H:%M:%S")

    with state_lock:
        if ip not in detected_attackers:
            detected_attackers[ip] = {
                "type": typ,
                "count": 1,
                "first_seen": now,
                "last_seen": now
            }

            block_ip(ip)
            send_network_alert(f"⚠️ ATTACKER: {ip}")

        else:
            detected_attackers[ip]["count"] += 1
            detected_attackers[ip]["last_seen"] = now
            detected_attackers[ip]["type"] = typ

        alerts.append({
            "time": now,
            "ip": ip,
            "type": typ,
            "detail": detail
        })

# ---------------- PACKET ----------------
def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    if src == local_ip:
        return

    now = time.time()

    if pkt.haslayer(ICMP):
        icmp_data[src].append(now)

    elif pkt.haslayer(TCP):
        flags = str(pkt[TCP].flags)
        port = pkt[TCP].dport
        traffic_data[src].append(("TCP", port, flags, now))

        if flags == "":
            add_alert(src,"NULL Scan",f"{port}")
        elif flags == "F":
            add_alert(src,"FIN Scan",f"{port}")

    elif pkt.haslayer(UDP):
        udp_data[src].append((pkt[UDP].dport, now))

# ---------------- DETECTION ----------------
def detect():
    while True:
        time.sleep(2)
        now = time.time()

        for ip, packets in list(traffic_data.items()):
            syn = [p for p in packets if "S" in p[2]]
            ports = len(set(p[1] for p in syn))

            if ports >= SCAN_THRESHOLD:
                add_alert(ip,"Port Scan",str(ports))

            if len(syn) >= FLOOD_THRESHOLD:
                add_alert(ip,"Flood",str(len(syn)))

        for ip, data in icmp_data.items():
            if len(data) >= ICMP_THRESHOLD:
                add_alert(ip,"Ping Sweep",str(len(data)))

# ---------------- NETWORK SCAN ----------------
def scan_network():
    devices = []
    target = "192.168.1.0/24"  # ⚠️ CHANGE

    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = ether/arp

    result = srp(pkt, timeout=2, verbose=0)[0]

    for s,r in result:
        devices.append({
            "ip": r.psrc,
            "mac": r.hwsrc
        })

    return devices

# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/data")
def data():
    return jsonify({
        "attackers":[{"ip":ip,**d} for ip,d in detected_attackers.items()],
        "alerts":alerts[-50:]
    })

@app.route("/block/<ip>", methods=["POST"])
def block(ip):
    block_ip(ip)
    return {"ok":True}

@app.route("/unblock/<ip>", methods=["POST"])
def unblock(ip):
    unblock_ip(ip)
    return {"ok":True}

@app.route("/network")
def network():
    return jsonify(scan_network())

# ---------------- RUN ----------------
def sniffing():
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    threading.Thread(target=sniffing, daemon=True).start()
    threading.Thread(target=detect, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)