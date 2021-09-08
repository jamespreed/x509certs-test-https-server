import tempfile
from collections import namedtuple
from pathlib import Path
from threading import Thread
from http.server import BaseHTTPRequestHandler, HTTPServer

import trustme
import ssl


CertPaths = namedtuple(
    'CertPaths', 
    ['temp_dir', 'ca', 'server', 'client']
)


class EchoHandler(BaseHTTPRequestHandler):
    """Simple request handler that echos the HTTP method and payload."""

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ECHO:GET')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ECHO:POST=' + body)


def create_test_certificates(*hosts: str) -> CertPaths:
    """Creates a CA certificate, server certificate, and client certificate
    in a temporary directory.

    args:
        hosts (str): the domain of the server for which the certificates are
            used.  If no arguments are passed, defaults to localhost.
    returns:
        certs (CertPath): object with the temporary directory and certificate
            paths as attributes.
    """
    if not hosts:
        hosts = ('localhost', '127.0.0.1')

    cert_temp_dir = tempfile.TemporaryDirectory()
    cert_temp_dir_path = Path(cert_temp_dir.name)

    ca = trustme.CA('test-CA')
    server_cert = ca.issue_cert(*hosts, organization_name='test-org')
    client_cert = ca.issue_cert(*('client@' + h for h in hosts))

    ca_path = cert_temp_dir_path / 'ca.pem'
    server_cert_path = cert_temp_dir_path / 'server.pem'
    client_cert_path = cert_temp_dir_path / 'client.pem'

    ca.cert_pem.write_to_path(ca_path)
    server_cert.private_key_and_cert_chain_pem.write_to_path(server_cert_path)
    client_cert.private_key_and_cert_chain_pem.write_to_path(client_cert_path)

    certs = CertPaths(
        cert_temp_dir_path.as_posix(),
        ca_path.as_posix(),
        server_cert_path.as_posix(),
        client_cert_path.as_posix()
    )

    return certs

def create_http_server(host:str = 'localhost', 
                       port:int = 4443,
                       handler:BaseHTTPRequestHandler = EchoHandler,
                       timeout:float = 0.2,
                       ) -> HTTPServer:
    """Creates a HTTP server on `host` using the `port`.  The requests are
    handled `handler`.

    args:
        host (str): host domain of the server
        port (int): port the serve runs on
        hander (BaseHTTPRequestHandler): request handler
        timeout (float): server time out in seconds
    return:
        httdp (HTTPServer): HTTP server object
    """
    httpd = HTTPServer((host, port), handler)
    httpd.timeout = timeout
    return httpd

def secure_server_socket(httpd: HTTPServer,
                         cert_path:str,
                         key_path:str = None,
                         ca_path:str = None,
                         ) -> HTTPServer:
    """Wraps the socket used by `httpd` in an SSL layer secured using the
    server certificate `certfile`.  The identities/hosts used when creating the
    certificates must match the server host.
    
    args:
        httpd (HTTPServer): the server to secure
        cert_path (path-like): path to the server certificate (PEM)
        key_path (path-like): path to the server certificate key, only needed
            if the `cert_path` PEM does not contain the private key in the 
            file.
        ca_path (path-like): optional path to the certificate (PEM) of the 
            certificate authority (CA).
    return:
        httpd (HTTPServer): the input httpd object with a wrapped socket
    """

    httpd.socket = ssl.wrap_socket(
        httpd.socket, 
        certfile=cert_path, 
        keyfile=key_path,
        ca_certs=ca_path,
        server_side=True
    )
    return httpd

def start_server_thread(httpd:HTTPServer) -> Thread:
    """Starts the `httpd` server in it's own thread.
    
    args:
        httpd (HTTPServer): the HTTP server to start in a thread.
    return:
        thread (Thread): the thread running the server.
    """
    thread = Thread(target=httpd.serve_forever, args=() )
    thread.daemon = True
    thread.start()

def main_example():
    """Example script of starting creating certs, using them to secure a
    server, launch the server, and make requests using the client cert."""

if __name__ == '__main__':
    main_example()