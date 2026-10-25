#!/usr/bin/env python3
"""Exercise the shipped origin configuration with real TLS and a local upstream.

Requires Python 3, OpenSSL and Nginx with the HTTP SSL / Real IP modules.
No Cloudflare credentials, ARTEX process, database, root access or public ports
are needed. Temporary loopback trust entries simulate Cloudflare socket peers;
they are never written back to the deployed configuration.
"""

import base64
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "packaging" / "nginx"
HOST = "artex.example.com"
TRUSTED_SOURCE = "127.0.0.2"


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def handle_request(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        record = {
            "method": self.command,
            "path": self.path,
            "body": body.decode("utf-8"),
            "headers": {key.lower(): value for key, value in self.headers.items()},
        }
        with self.server.records_lock:
            self.server.records.append(record)

        if self.path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "public, max-age=86400")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"data: first\n\n")
            self.wfile.flush()
            self.server.release_stream.wait(5)
            try:
                self.wfile.write(b"data: second\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True
            return

        if self.path == "/ws":
            if (
                self.headers.get("Upgrade", "").lower() != "websocket"
                or self.headers.get("Connection", "").lower() != "upgrade"
            ):
                self.send_error(400, "Missing WebSocket upgrade headers")
                return
            accept = base64.b64encode(
                hashlib.sha1(
                    (self.headers["Sec-WebSocket-Key"]
                     + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
                ).digest()
            ).decode("ascii")
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()
            self.connection.settimeout(3)
            # A masked empty client ping and an unmasked empty server pong.
            if self.rfile.read(6) == b"\x89\x80\x01\x02\x03\x04":
                self.wfile.write(b"\x8a\x00")
                self.wfile.flush()
            self.close_connection = True
            return

        data = json.dumps(record).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        self.wfile.write(data)

    do_GET = handle_request
    do_POST = handle_request


class OriginConnection(http.client.HTTPSConnection):
    def __init__(self, fixture, source=TRUSTED_SOURCE, ipv6=False):
        super().__init__(HOST, fixture.port, timeout=3, context=fixture.context())
        self.source = source
        self.destination = "::1" if ipv6 else "127.0.0.1"

    def connect(self):
        raw = socket.socket(socket.AF_INET6 if ":" in self.destination else socket.AF_INET)
        raw.settimeout(self.timeout)
        try:
            raw.bind((self.source, 0))
            raw.connect((self.destination, self.port))
            self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
        except BaseException:
            raw.close()
            raise


class NginxFixture:
    def __init__(self):
        self.nginx = os.environ.get("NGINX_BIN") or shutil.which("nginx")
        if not self.nginx:
            raise RuntimeError("Nginx is required; install it or set NGINX_BIN")
        self.port = unused_port()
        self.temp = tempfile.TemporaryDirectory(prefix="artex-nginx-test-")
        self.directory = Path(self.temp.name)
        self.process = None
        self.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.upstream.daemon_threads = True
        self.upstream.records = []
        self.upstream.records_lock = threading.Lock()
        self.upstream.release_stream = threading.Event()
        self.upstream_thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.upstream_thread.start()

    def context(self, version=None):
        context = ssl.create_default_context(cafile=str(self.directory / "certificate.pem"))
        if version is not None:
            context.minimum_version = version
            context.maximum_version = version
        return context

    def start(self):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}",
             "-keyout", str(self.directory / "key.pem"),
             "-out", str(self.directory / "certificate.pem")],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15,
        )
        realip = (CONFIG_DIR / "cloudflare-realip.conf").read_text()
        peers = (CONFIG_DIR / "cloudflare-peers.geo").read_text()
        # Only these copies trust the simulated edge peers. 127.0.0.1 remains
        # untrusted so spoofed CF/XFF headers cannot authorize a direct request.
        (self.directory / "cloudflare-realip.conf").write_text(
            realip + "\nset_real_ip_from 127.0.0.2/32;\nset_real_ip_from ::1/128;\n"
        )
        (self.directory / "cloudflare-peers.geo").write_text(
            peers + "\n127.0.0.2/32 1;\n::1/128 1;\n"
        )
        template = (CONFIG_DIR / "artex-cloudflare.conf.example").read_text()
        replacements = {
            "/etc/nginx/snippets/artex/cloudflare-realip.conf": str(self.directory / "cloudflare-realip.conf"),
            "/etc/nginx/snippets/artex/cloudflare-peers.geo": str(self.directory / "cloudflare-peers.geo"),
            "/etc/nginx/ssl/artex/fullchain.pem": str(self.directory / "certificate.pem"),
            "/etc/nginx/ssl/artex/privkey.pem": str(self.directory / "key.pem"),
            "http://127.0.0.1:8787": f"http://127.0.0.1:{self.upstream.server_port}",
        }
        for old, new in replacements.items():
            if old not in template:
                raise RuntimeError(f"Template endpoint changed; update test fixture: {old}")
            template = template.replace(old, new)
        template = re.sub(r"(listen\s+)443\b", rf"\g<1>127.0.0.1:{self.port}", template)
        template = re.sub(r"(listen\s+)\[::\]:443\b", rf"\g<1>[::1]:{self.port}", template)
        (self.directory / "origin.conf").write_text(template)
        config = self.directory / "nginx.conf"
        config.write_text(
            "daemon off;\nmaster_process off;\nworker_processes 1;\n"
            f"pid {self.directory}/nginx.pid;\n"
            f"error_log {self.directory}/error.log notice;\n"
            "events { worker_connections 128; }\n"
            "http {\naccess_log off;\n"
            f"client_body_temp_path {self.directory}/body;\n"
            f"proxy_temp_path {self.directory}/proxy;\n"
            f"include {self.directory}/origin.conf;\n}}\n"
        )
        command = [self.nginx, "-p", str(self.directory) + "/", "-c", str(config)]
        result = subprocess.run(command + ["-t"], capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(self.process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.02)
        raise RuntimeError("Nginx did not start within five seconds")

    def close(self):
        self.upstream.release_stream.set()
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=5)
        self.upstream.shutdown()
        self.upstream.server_close()
        self.upstream_thread.join(timeout=2)
        self.temp.cleanup()

    def count_requests(self):
        with self.upstream.records_lock:
            return len(self.upstream.records)


class HardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = NginxFixture()
        cls.addClassCleanup(cls.fixture.close)
        cls.fixture.start()

    def request(self, method="GET", path="/echo", headers=None, body=None,
                source=TRUSTED_SOURCE, ipv6=False):
        conn = OriginConnection(self.fixture, source=source, ipv6=ipv6)
        self.addCleanup(conn.close)
        fields = {"Host": HOST, "CF-Connecting-IP": "198.51.100.23"}
        fields.update(headers or {})
        conn.request(method, path, body=body, headers=fields)
        return conn.getresponse()

    def test_cloudflare_ipv4_and_ipv6_lists_are_consistent(self):
        realip = (CONFIG_DIR / "cloudflare-realip.conf").read_text()
        peers = (CONFIG_DIR / "cloudflare-peers.geo").read_text()
        trusted = re.findall(r"^\s*set_real_ip_from\s+(\S+);", realip, re.MULTILINE)
        allowed = re.findall(r"^\s*(\S+)\s+1;", peers, re.MULTILINE)
        self.assertTrue(trusted)
        self.assertEqual(set(trusted), set(allowed))
        self.assertEqual(len(trusted), len(set(trusted)))
        self.assertEqual(len(allowed), len(set(allowed)))
        networks = [ipaddress.ip_network(cidr, strict=True) for cidr in trusted]
        self.assertEqual({network.version for network in networks}, {4, 6})
        for network in networks:
            self.assertGreater(network.prefixlen, 0)
            self.assertTrue(network.is_global, str(network))

    def test_valid_sni_negotiates_tls12_and_tls13(self):
        for version, expected in ((ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
                                  (ssl.TLSVersion.TLSv1_3, "TLSv1.3")):
            with self.subTest(version=expected):
                with socket.create_connection(("127.0.0.1", self.fixture.port), timeout=3) as raw:
                    with self.fixture.context(version).wrap_socket(raw, server_hostname=HOST) as tls:
                        self.assertEqual(tls.version(), expected)
                        self.assertTrue(tls.getpeercert())

    def test_wrong_or_missing_sni_rejects_before_certificate(self):
        for protocol in ("-tls1_2", "-tls1_3"):
            for name_args in (["-noservername"], ["-servername", "rejected.invalid"]):
                with self.subTest(protocol=protocol, sni=name_args):
                    result = subprocess.run(
                        ["openssl", "s_client", "-connect", f"127.0.0.1:{self.fixture.port}",
                         "-showcerts", protocol, *name_args],
                        input=b"", capture_output=True, timeout=5,
                    )
                    output = (result.stdout + result.stderr).decode(errors="replace")
                    self.assertNotEqual(result.returncode, 0, output)
                    self.assertNotIn("BEGIN CERTIFICATE", output)
                    self.assertRegex(output.lower(), r"unrecognized[ _]name")

    def test_untrusted_peer_cannot_authorize_itself_with_headers(self):
        before = self.fixture.count_requests()
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.request(source="127.0.0.1", headers={
                "CF-Connecting-IP": "173.245.48.1",
                "X-Forwarded-For": "173.245.48.1",
                "X-Real-IP": "173.245.48.1",
            })
        self.assertEqual(self.fixture.count_requests(), before)

    def test_valid_sni_with_wrong_host_never_reaches_upstream(self):
        before = self.fixture.count_requests()
        for host in ("rejected.invalid", "rejected.invalid:443"):
            with self.subTest(host=host):
                with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
                    self.request(headers={"Host": host})
        self.assertEqual(self.fixture.count_requests(), before)

    def test_absolute_request_target_and_host_must_both_match(self):
        before = self.fixture.count_requests()
        for target, host in (("https://rejected.invalid/echo", HOST),
                             (f"https://{HOST}/echo", "rejected.invalid")):
            with self.subTest(target=target, host=host):
                with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
                    self.request(path=target, headers={"Host": host})
        self.assertEqual(self.fixture.count_requests(), before)

    def test_valid_host_accepts_case_variants_and_https_port(self):
        for host in (HOST.upper(), f"{HOST}:443"):
            with self.subTest(host=host):
                response = self.request(headers={"Host": host})
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read())["headers"]["host"], HOST)

    def test_trusted_peer_restores_visitor_and_sanitizes_forwarded_headers(self):
        response = self.request(headers={
            "CF-Connecting-IP": "198.51.100.23",
            "X-Forwarded-For": "1.2.3.4, 5.6.7.8",
            "X-Real-IP": "1.2.3.4",
            "X-Forwarded-Proto": "http",
            "Forwarded": "for=1.2.3.4;proto=http",
            "True-Client-IP": "1.2.3.4",
            "CF-Connecting-IPv6": "2001:db8::bad",
        })
        self.assertEqual(response.status, 200)
        headers = json.loads(response.read())["headers"]
        self.assertEqual(headers["x-real-ip"], "198.51.100.23")
        self.assertEqual(headers["x-forwarded-for"], "198.51.100.23")
        self.assertEqual(headers["x-forwarded-proto"], "https")
        self.assertEqual(headers["host"], HOST)
        for name in ("forwarded", "true-client-ip", "cf-connecting-ipv6"):
            self.assertNotIn(name, headers)
        if "cf-connecting-ip" in headers:
            self.assertEqual(headers["cf-connecting-ip"], "198.51.100.23")

    def test_ipv6_peer_and_visitor(self):
        response = self.request(source="::1", ipv6=True,
                                headers={"CF-Connecting-IP": "2001:db8::23"})
        self.assertEqual(response.status, 200)
        headers = json.loads(response.read())["headers"]
        self.assertEqual(headers["x-real-ip"], "2001:db8::23")
        self.assertEqual(headers["x-forwarded-for"], "2001:db8::23")

    def test_gate_post_method_body_and_query_are_preserved(self):
        body = "password=local-test-only%26value"
        response = self.request("POST", "/g-test?next=%2F", body=body,
                                headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(response.status, 200)
        record = json.loads(response.read())
        self.assertEqual(record["method"], "POST")
        self.assertEqual(record["path"], "/g-test?next=%2F")
        self.assertEqual(record["body"], body)

    def test_upload_larger_than_default_nginx_limit_reaches_upstream(self):
        body = "x" * (1024 * 1024 + 1)
        response = self.request("POST", "/upload", body=body)
        self.assertEqual(response.status, 200)
        received = json.loads(response.read())["body"]
        self.assertEqual(len(received), len(body))
        self.assertEqual(hashlib.sha256(received.encode()).digest(),
                         hashlib.sha256(body.encode()).digest())

    def test_upload_above_application_limit_rejected_without_upstream(self):
        before = self.fixture.count_requests()
        response = self.request("POST", "/upload", headers={
            "Content-Length": str(512 * 1024 * 1024 + 1),
        })
        self.assertEqual(response.status, 413)
        response.read()
        self.assertEqual(self.fixture.count_requests(), before)

    def test_upstream_cache_headers_are_replaced(self):
        response = self.request()
        response.read()
        cache = response.getheader("Cache-Control", "").lower()
        self.assertIn("private", cache)
        self.assertIn("no-store", cache)
        self.assertNotIn("public", cache)
        self.assertNotIn("max-age=86400", cache)

    def test_sse_first_event_arrives_before_upstream_finishes(self):
        self.fixture.upstream.release_stream.clear()
        try:
            response = self.request(path="/events")
            self.assertEqual(response.status, 200)
            self.assertEqual(response.readline(), b"data: first\n")
            self.assertEqual(response.readline(), b"\n")
            self.assertFalse(self.fixture.upstream.release_stream.is_set())
            self.fixture.upstream.release_stream.set()
            self.assertEqual(response.readline(), b"data: second\n")
            response.read()
        finally:
            self.fixture.upstream.release_stream.set()

    def test_websocket_upgrade_and_bidirectional_frames(self):
        conn = OriginConnection(self.fixture)
        self.addCleanup(conn.close)
        conn.connect()
        conn.sock.sendall((
            f"GET /ws HTTP/1.1\r\nHost: {HOST}\r\n"
            "CF-Connecting-IP: 198.51.100.23\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        ).encode("ascii"))
        stream = conn.sock.makefile("rb")
        self.addCleanup(stream.close)
        self.assertIn(b" 101 ", stream.readline())
        headers = {}
        while True:
            line = stream.readline()
            if line == b"\r\n":
                break
            self.assertTrue(line, "Truncated WebSocket upgrade response")
            key, value = line.decode().split(":", 1)
            headers[key.lower()] = value.strip()
        self.assertEqual(headers["upgrade"].lower(), "websocket")
        self.assertEqual(headers["sec-websocket-accept"], "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        conn.sock.sendall(b"\x89\x80\x01\x02\x03\x04")
        self.assertEqual(stream.read(2), b"\x8a\x00")


if __name__ == "__main__":
    unittest.main(verbosity=2)
