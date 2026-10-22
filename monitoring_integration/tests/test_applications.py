"""Real loopback TLS regressions; routed FTP/DNS checks are in live_regressions."""
import http.server
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
from application_services import check


class TLSApplicationTests(unittest.TestCase):
    def setUp(self):
        executable=shutil.which('openssl')
        if not executable:
            candidate=Path('C:/Program Files/Git/mingw64/bin/openssl.exe')
            executable=str(candidate) if candidate.is_file() else None
        if not executable:
            self.skipTest('OpenSSL executable unavailable for real loopback TLS test')
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory=Path(temporary.name)
        subprocess.run([executable,'req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-keyout',str(self.directory/'private-key.pem'),'-out',str(self.directory/'certificate.pem'),
            '-subj','/CN=cnpro-loopback-test','-addext','subjectAltName=IP:127.0.0.1'],
            check=True,capture_output=True)
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                payload=b'CNPRO live service TLS regression'
                self.send_response(200)
                self.send_header('Content-Length',str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self,*args):
                pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.directory/'certificate.pem',self.directory/'private-key.pem')
        server.socket=context.wrap_socket(server.socket,server_side=True)
        worker=threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        def close():
            server.shutdown();server.server_close();worker.join(timeout=3)
        self.addCleanup(close)
        self.destination='127.0.0.1:'+str(server.server_port)

    def test_https_requires_verified_tls_and_real_http_response(self):
        result=check('https',self.destination,self.directory)
        self.assertTrue(result['success'],result)
        self.assertTrue(result['certificate_and_hostname_verified'])
        self.assertIn(result['tls_version'],('TLSv1.2','TLSv1.3'))
        self.assertEqual(result['http_status'],200)
        self.assertGreater(result['bytes_received'],0)

    def test_untrusted_tls_is_rejected_instead_of_counting_an_open_port(self):
        result=check('https',self.destination,self.directory,invalid=True)
        self.assertFalse(result['success'])
        self.assertEqual(result['error_type'],'SSLCertVerificationError')
