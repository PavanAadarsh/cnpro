"""Genuine lab TLS/FTP services and protocol clients (not transport probes).

Credentials and private keys are generated per ignored live run, never constants.
FTP uses passive data port 20, matching the supplied explicit port 20/21 ACLs.
"""
import ftplib
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import socket
import ssl
import sys
import threading
import time


def resolver_for(vlan):
    return '192.168.50.13' if vlan in (60, 70) else '203.0.113.2'


def serve(role, directory, handler):
    directory = Path(directory)
    http_server = http.server.ThreadingHTTPServer(('0.0.0.0', 80), handler)
    threading.Thread(target=http_server.serve_forever, daemon=True).start()
    if role in ('SRV-RESEARCH', 'SRV-ADMIN', 'INTERNET-SRV'):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(directory/'certificate.pem', directory/'private-key.pem')
        https = http.server.ThreadingHTTPServer(('0.0.0.0', 443), handler)
        https.socket = context.wrap_socket(https.socket, server_side=True)
        threading.Thread(target=https.serve_forever, daemon=True).start()
    if role == 'SRV-DB':
        from pyftpdlib.authorizers import DummyAuthorizer
        from pyftpdlib.handlers import FTPHandler
        from pyftpdlib.servers import FTPServer
        credentials = json.loads((directory/'ftp-credentials.json').read_text())
        authorizer = DummyAuthorizer()
        authorizer.add_user(credentials['username'], credentials['password'], str(directory/'ftp-root'), perm='elr')
        class LabFTP(FTPHandler):
            passive_ports = [20]
            auth_failed_timeout = 0.1
            def log(self, *args, **kwargs):
                pass  # Authentication evidence is recorded by clients, without secrets.
            def logerror(self, *args, **kwargs):
                pass
        LabFTP.authorizer = authorizer
        FTPServer(('0.0.0.0', 21), LabFTP).serve_forever()
    else:
        threading.Event().wait()


def check(mode, destination, directory, invalid=False, anonymous=False):
    started = time.time_ns()
    row = dict(started_ns=started, protocol=mode, destination=destination, success=False)
    try:
        if mode == 'resolve':
            row['addresses'] = sorted({a[4][0] for a in socket.getaddrinfo(destination, None, socket.AF_INET)})
            row['success'] = bool(row['addresses'])
        elif mode in ('http', 'https'):
            context = ssl.create_default_context(cafile=None if invalid else str(Path(directory)/'certificate.pem')) if mode == 'https' else None
            client = (http.client.HTTPSConnection(destination, timeout=1.5, context=context) if context
                      else http.client.HTTPConnection(destination, timeout=1.5))
            try:
                client.connect()
                if context:
                    row.update(tls_version=client.sock.version(), cipher=client.sock.cipher()[0],
                        peer_certificate_sha256=hashlib.sha256(client.sock.getpeercert(binary_form=True)).hexdigest(),
                        certificate_and_hostname_verified=True)
                client.request('GET', '/')
                response = client.getresponse()
                payload = response.read()
                row.update(http_status=response.status, bytes_received=len(payload))
                row['success'] = response.status == 200 and payload.startswith(b'CNPRO live service')
            finally:
                client.close()
        elif mode == 'ftp':
            credentials = json.loads((Path(directory)/'ftp-credentials.json').read_text())
            class MeasuredFTP(ftplib.FTP):
                def makepasv(self):
                    address = super().makepasv()
                    row['data_port'] = address[1]
                    return address
            with MeasuredFTP(timeout=1.5) as client:
                row['banner'] = client.connect(destination, 21)
                password = 'invalid-' + credentials['password'] if invalid else credentials['password']
                try:
                    row['login_reply'] = client.login('anonymous' if anonymous else credentials['username'], password)
                    row['authenticated'] = True
                    if not invalid:
                        data = bytearray()
                        row['transfer_reply'] = client.retrbinary('RETR sample.txt', data.extend)
                        row['bytes_received'] = len(data)
                        row['success'] = bytes(data) == b'CNPRO authenticated FTP sample\n'
                except ftplib.error_perm as exc:
                    row['authenticated'] = False
                    row['reply_code'] = str(exc)[:3]
                    row['success'] = False
                client.quit()
        else:
            raise ValueError('unknown protocol')
    except (OSError, ftplib.Error, ssl.SSLError) as exc:
        row['error_type'] = type(exc).__name__
    row['completed_ns'] = time.time_ns()
    return row


if __name__ == '__main__':
    print(json.dumps(check(*sys.argv[1:4], invalid=len(sys.argv)>4 and sys.argv[4] in ('invalid','anonymous'), anonymous=len(sys.argv)>4 and sys.argv[4]=='anonymous')))
