import http.server
import socketserver

PORT = 80

class SimpleHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        html = """
        <html>
            <head><title>Website on a HTTP Server</title></head>
        </html>
        """
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format, *args):
        return  # Suppress logs

with socketserver.TCPServer(("", PORT), SimpleHandler) as httpd:
    print(f"Serving HTTP on port {PORT}...")
    httpd.serve_forever()