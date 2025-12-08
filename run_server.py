import http.server
import ssl

port = 443
handler = http.server.SimpleHTTPRequestHandler

httpd = http.server.HTTPServer(("0.0.0.0", port), handler)

# Modern replacement for wrap_socket
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print(f"Serving HTTPS on port {port}...")
httpd.serve_forever()

