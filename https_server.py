from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import BaseServer
from ssl import SSLContext, PROTOCOL_TLS_SERVER
from OpenSSL import crypto, SSL

# Function to create a self-signed certificate
def create_self_signed_cert(cert_file, key_file):
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "Minnesota"
    cert.get_subject().L = "Minneapolis"
    cert.get_subject().O = "My Company"
    cert.get_subject().OU = "My Organization"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(0)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    with open(cert_file, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(key_file, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

cert_file = "selfsigned.crt"
key_file = "private.key"

create_self_signed_cert(cert_file, key_file)

# Setting up SSL context
context = SSLContext(PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=cert_file, keyfile=key_file)

# Setting up HTTP Server
httpd = HTTPServer(('localhost', 4443), SimpleHTTPRequestHandler)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("Serving HTTPS on", httpd.server_address)
httpd.serve_forever()
