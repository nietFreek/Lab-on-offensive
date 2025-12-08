from http.server import SimpleHTTPRequestHandler, HTTPServer

class RedirectHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        host = self.headers.get("Host")
        https_url = f"https://{host}{self.path}"
        self.send_header("Location", https_url)
        self.end_headers()

HTTPServer(("0.0.0.0", 80), RedirectHandler).serve_forever()
