from http.server import HTTPServer, BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
import urllib.parse
import ssl
import os
import threading
import sys

# Configuration
HTTPS_PORT = 443
HTTP_PORT = 80

# Resolve paths relative to this script's location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(SCRIPT_DIR, '..', 'server.crt')
KEY_FILE = os.path.join(SCRIPT_DIR, '..', 'server.key')

# Credentials
VALID_USER = "admin"
VALID_PASS = "secret123"

class RedirectHandler(BaseHTTPRequestHandler):
    def do_request(self):
        self.send_response(301)
        # Check if Host header is present to preserve the hostname
        host = self.headers.get("Host")
        if not host:
            host = "localhost" # Fallback
        
        # Strip port from host if present (e.g. localhost:80 -> localhost)
        if ':' in host:
            host = host.split(':')[0]
            
        https_url = f"https://{host}{self.path}"
        self.send_header("Location", https_url)
        self.end_headers()
        print(f"[HTTP] Redirected client to {https_url}")

    # Redirect ALL methods
    def do_GET(self): self.do_request()
    def do_POST(self): self.do_request()
    def do_HEAD(self): self.do_request()
    def do_OPTIONS(self): self.do_request()
    def do_PUT(self): self.do_request()
    def do_DELETE(self): self.do_request()
    def do_PATCH(self): self.do_request()


class LoginHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/login":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.send_header("Set-Cookie", "session_id=12345; Secure; HttpOnly") # Simulate secure cookie
            # Add HSTS header to test stripping
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            self.end_headers()
            
            # Check if login.html exists in current dir
            file_path = "login.html"
            if not os.path.exists(file_path):
                 # Try absolute path based on script location
                 file_path = os.path.join(os.path.dirname(__file__), "login.html")

            with open(file_path, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "Page Not Found")

    def do_POST(self):
        if self.path == "/login":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            
            # --- ADDED FOR DEMONSTATION PURPOSES ---
            print(f"\n[!] SERVER RECEIVED CREDENTIALS (ENCRYPTED TUNNEL):")
            print(f"    User: {username}")
            print(f"    Pass: {password}\n")
            # ---------------------------------------
            
            if username == VALID_USER and password == VALID_PASS:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>Login Approved</h1><p>Welcome to the secure area.</p>")
            else:
                self.send_response(200) # Only 200 OK usually displays the full HTML body in browsers
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>Login Failed</h1><p>Incorrect credentials.</p><a href='/'>Try again</a>")
        else:
            self.send_error(404, "Page Not Found")


class SafeThreadingHTTPServer(ThreadingHTTPServer):
    """
    A ThreadingHTTPServer that catches SSL errors during the handshake (get_request)
    so the server doesn't crash on a bad connection (like a port scan or upgrade failure).
    """
    def get_request(self):
        try:
            sock, addr = super().get_request()
            return sock, addr
        except ssl.SSLError as e:
            # print(f"[Server] Handshake error from client: {e}")
            raise # Let handle_error catch it if possible, or suppress here if needed? 
                  # Actually get_request failure usually crashes serve_forever loop if not caught.
                  # But socket.accept() raises OSError. wrap_socket raises SSLError.
            # We return None or recursive call? Recursive call is dangerous (infinite loop).
            # The BaseServer loop expects (sock, addr).
            pass
        except OSError as e:
            # print(f"[Server] Socket error: {e}")
            pass
        
        # If we failed, we have no socket to return.
        # This will cause TypeError in finish_request because it expects unpacking.
        # We have to let the exception bubble or handle it in the loop.
        # The standard serve_forever loop:
        # try:
        #    request, client_address = self.get_request()
        # except OSError: return
        # So raising OSError is safe?
        raise OSError("Handshake Failed")

    def handle_error(self, request, client_address):
        # Override to prevent spamming stderr on simple disconnects
        # print(f"[Server] Error handling request from {client_address}: {sys.exc_info()[1]}")
        pass

def run_https_server():
    # Ensure certs exist (generated by setup_certs.py in parent dir)
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print(f"Error: Certificates not found at {CERT_FILE}. Run setup_certs.py in root first.")
        return

    server_address = ('0.0.0.0', HTTPS_PORT)
    # Use SafeThreadingHTTPServer instead of HTTPServer
    try:
        httpd = SafeThreadingHTTPServer(server_address, LoginHandler)
    except NameError:
         # Fallback for older python if ThreadingHTTPServer not available? Standard since 3.7
         print("Warning: ThreadingHTTPServer not found. Using single-threaded.")
         httpd = HTTPServer(server_address, LoginHandler)

    # Wrap with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    
    # Wrap the socket manually
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print(f"Secure Login Server running on https://0.0.0.0:{HTTPS_PORT}")
    try:
        httpd.serve_forever()
    except Exception as e:
        print(f"[CRITICAL] HTTPS Server crashed: {e}")


def run_http_redirect_server():
    server_address = ('0.0.0.0', HTTP_PORT)
    httpd = HTTPServer(server_address, RedirectHandler)
    print(f"HTTP Redirect Server running on http://0.0.0.0:{HTTP_PORT}")
    httpd.serve_forever()

if __name__ == '__main__':
    print("Starting Fake Server infrastructure...")
    print("Ensure you add '10.0.0.182 mybank.local' to your hosts file on the victim machine!")

    # Start HTTP Redirector in a separate thread
    t_http = threading.Thread(target=run_http_redirect_server, daemon=True)
    t_http.start()

    # Start HTTPS Server in the main thread
    try:
        run_https_server()
    except KeyboardInterrupt:
        print("\nStopping servers...")

