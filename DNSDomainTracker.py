from scapy.all import DNS, DNSRR

class DNSDomainTracker:
    def __init__(self, domain, logger=None):
        self.domain = domain.encode() if isinstance(domain, str) else domain
        self.ips_v4 = set()
        self.ips_v6 = set()
        self.logger = logger

    def log(self, msg):
        if self.logger:
            self.logger(msg)
        else:
            print(msg)

    def __call__(self, pkt):
        if not pkt.haslayer(DNS) or not pkt[DNS].an:
            return False 

        dns = pkt[DNS]

        for i in range(dns.ancount):
            rr = dns.an[i]

            if self.domain in rr.rrname:
                if rr.type == 1:  # A
                    self.ips_v4.add(rr.rdata)
                    self.log(f"[DNS] Learned IPv4 {rr.rdata}")

                elif rr.type == 28:  # AAAA
                    self.ips_v6.add(rr.rdata)
                    self.log(f"[DNS] Learned IPv6 {rr.rdata}")

        return False