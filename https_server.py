import http.server, ssl

keyfile = r'c:\Users\user\OneDrive\Desktop\ADVANCED CRYPTOGRAPHY\crypto_project\private_key.pem'
certfile = r'c:\Users\user\OneDrive\Desktop\ADVANCED CRYPTOGRAPHY\crypto_project\certificate.pem'

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=certfile, keyfile=keyfile)

server = http.server.HTTPServer(('localhost', 4443), http.server.SimpleHTTPRequestHandler)
server.socket = context.wrap_socket(server.socket, server_side=True)
print("HTTPS server running at https://localhost:4443")
server.serve_forever()