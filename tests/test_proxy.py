"""Tests for the proxy. Run from the project root with:

    python -m unittest discover -s tests -v

They only use the standard library and talk to servers started on localhost,
so no Internet connection is needed (except one DNS-failure test that expects
the lookup of a ".invalid" name to fail).
"""

import http.client
import os
import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy.cache import compute_lifetime  # noqa: E402
from proxy.config import Config  # noqa: E402
from proxy.errors import BadRequest  # noqa: E402
from proxy.http_parser import (  # noqa: E402
    ConnectionClosedEarly,
    Headers,
    parse_request,
    read_head,
)
from proxy.server import ProxyServer  # noqa: E402


# ---------------------------------------------------------------------------
# A tiny origin server used as the "destination" in the tests
# ---------------------------------------------------------------------------
class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output quiet
        pass

    def _count(self):
        with self.server.lock:
            self.server.hits[self.path] = self.server.hits.get(self.path, 0) + 1

    def _reply(self, status, body, headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the proxy gave up waiting (timeout tests)

    def do_GET(self):
        self._count()
        path = self.path.split("?")[0]
        if path == "/cacheable":
            self._reply(200, b"cacheable body", [("Cache-Control", "max-age=60")])
        elif path == "/short":
            self._reply(200, b"short lived", [("Cache-Control", "max-age=1")])
        elif path == "/nostore":
            self._reply(200, b"never stored", [("Cache-Control", "no-store")])
        elif path == "/cookie":
            self._reply(200, b"cookie", [("Cache-Control", "max-age=60"), ("Set-Cookie", "a=b")])
        elif path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Cache-Control", "max-age=60")
            self.end_headers()
            self.wfile.write(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
        elif path == "/slow":
            time.sleep(0.3)
            self._reply(200, b"slow")
        elif path == "/hang":
            time.sleep(3)
            self._reply(200, b"too late")
        elif path == "/headers":
            text = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
            self._reply(200, text.encode())
        elif path == "/missing":
            self._reply(404, b"nope")
        else:
            self._reply(404, b"unknown")

    def do_POST(self):
        self._count()
        length = int(self.headers.get("Content-Length", 0))
        self._reply(200, self.rfile.read(length))


class EchoServer:
    """Raw TCP echo server: used as the target of CONNECT tunnels."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        with conn:
            while True:
                data = conn.recv(1024)
                if not data:
                    return
                conn.sendall(data)

    def close(self):
        self.sock.close()


def start_proxy(**overrides):
    config = Config(port=0, insecure_testing=True, upstream_timeout=2.0, client_timeout=3.0)
    for key, value in overrides.items():
        setattr(config, key, value)
    server = ProxyServer(config)
    server.bind()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server._test_thread = thread
    return server


def stop_proxy(server):
    server.shutdown()
    server._test_thread.join(timeout=3)


class ProxyTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.origin = ThreadingHTTPServer(("127.0.0.1", 0), OriginHandler)
        cls.origin.daemon_threads = True
        cls.origin.lock = threading.Lock()
        cls.origin.hits = {}
        cls.origin_port = cls.origin.server_address[1]
        threading.Thread(target=cls.origin.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.origin.shutdown()
        cls.origin.server_close()

    def setUp(self):
        self.origin.hits.clear()
        self.proxy = start_proxy()
        self.addCleanup(stop_proxy, self.proxy)

    def fetch(self, path, method="GET", body=None, headers=None, proxy=None, host=None):
        proxy = proxy or self.proxy
        conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=6)
        url = f"http://{host or '127.0.0.1:%d' % self.origin_port}{path}"
        conn.request(method, url, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response, data

    def raw(self, payload_chunks, proxy=None, delay=0.0):
        """Send raw bytes to the proxy and return everything it answers."""
        proxy = proxy or self.proxy
        sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        for chunk in payload_chunks:
            sock.sendall(chunk)
            if delay:
                time.sleep(delay)
        received = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            received += data
        sock.close()
        return received


# ---------------------------------------------------------------------------
# STAGE 3 - parsing and basic forwarding
# ---------------------------------------------------------------------------
class ParserTests(unittest.TestCase):
    def test_absolute_url_with_port_and_query(self):
        req = parse_request(b"GET http://Example.com:8080/a/b?x=1 HTTP/1.1\r\nHost: example.com:8080")
        self.assertEqual((req.method, req.host, req.port, req.path), ("GET", "example.com", 8080, "/a/b?x=1"))

    def test_default_port_and_root_path(self):
        req = parse_request(b"GET http://example.com HTTP/1.1\r\nHost: example.com")
        self.assertEqual((req.port, req.path), (80, "/"))

    def test_connect_target(self):
        req = parse_request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443")
        self.assertTrue(req.is_connect)
        self.assertEqual((req.host, req.port), ("example.com", 443))

    def test_connect_ipv6_target(self):
        req = parse_request(b"CONNECT [2001:db8::1]:443 HTTP/1.1")
        self.assertEqual((req.host, req.port), ("2001:db8::1", 443))

    def test_headers_are_case_insensitive(self):
        req = parse_request(b"GET http://a.com/ HTTP/1.1\r\nhOsT: a.com")
        self.assertEqual(req.headers.get("Host"), "a.com")

    def test_malformed_requests_are_rejected(self):
        bad = [
            b"GET / HTTP/1.1\r\nHost: a",                      # origin-form
            b"GET http://a.com/ HTTP/2.0",                     # bad version
            b"GET http://a.com/",                              # missing version
            b"get http://a.com/ HTTP/1.1",                     # lowercase method
            b"GET https://a.com/ HTTP/1.1",                    # https needs CONNECT
            b"GET ftp://a.com/ HTTP/1.1",                      # unsupported scheme
            b"GET http://a.com/ HTTP/1.1\r\nBroken header",    # no colon
            b"GET http://a.com/ HTTP/1.1\r\nHost : a.com",     # space before colon
            b"CONNECT example.com HTTP/1.1",                   # no port
        ]
        for head in bad:
            with self.subTest(head=head):
                with self.assertRaises(BadRequest):
                    parse_request(head)

    def test_read_head_when_delimiter_is_split_between_reads(self):
        class FakeSocket:
            def __init__(self, chunks):
                self.chunks = list(chunks)

            def recv(self, _size):
                return self.chunks.pop(0) if self.chunks else b""

        sock = FakeSocket([b"GET http://a.com/ HTTP/1.1\r\nHost: a\r", b"\n\r", b"\nBODY"])
        head, rest = read_head(sock, 1024)
        self.assertEqual(head, b"GET http://a.com/ HTTP/1.1\r\nHost: a")
        self.assertEqual(rest, b"BODY")

    def test_read_head_reports_early_close(self):
        class FakeSocket:
            def recv(self, _size):
                return b""

        with self.assertRaises(ConnectionClosedEarly):
            read_head(FakeSocket(), 1024)


class ForwardingTests(ProxyTestCase):
    def test_get_is_forwarded(self):
        response, body = self.fetch("/slow")
        self.assertEqual((response.status, body), (200, b"slow"))

    def test_post_body_is_forwarded(self):
        response, body = self.fetch("/echo", method="POST", body=b"hello=world")
        self.assertEqual((response.status, body), (200, b"hello=world"))

    def test_status_codes_pass_through(self):
        response, body = self.fetch("/missing")
        self.assertEqual((response.status, body), (404, b"nope"))

    def test_request_is_rewritten_for_the_origin(self):
        _, body = self.fetch("/headers", headers={"Proxy-Connection": "Keep-Alive", "X-Custom": "1"})
        text = body.decode()
        self.assertIn("X-Custom: 1", text)
        self.assertNotIn("Proxy-Connection", text)
        self.assertIn(f"Host: 127.0.0.1:{self.origin_port}", text)
        self.assertIn("Connection: close", text)

    def test_head_split_into_tiny_packets(self):
        request = (
            f"GET http://127.0.0.1:{self.origin_port}/cacheable HTTP/1.1\r\nHost: x\r\n\r\n"
        ).encode()
        pieces = [request[i:i + 5] for i in range(0, len(request), 5)]
        answer = self.raw(pieces, delay=0.01)
        self.assertIn(b"200 OK", answer)
        self.assertTrue(answer.endswith(b"cacheable body"))


# ---------------------------------------------------------------------------
# STAGE 4 - errors, limits, concurrency
# ---------------------------------------------------------------------------
class ConnectionHandlingTests(ProxyTestCase):
    def test_origin_form_request_gets_400(self):
        answer = self.raw([b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"])
        self.assertTrue(answer.startswith(b"HTTP/1.1 400"))

    def test_unresolvable_host_gets_502(self):
        response, _ = self.fetch("/", host="no-such-host.invalid")
        self.assertEqual(response.status, 502)

    def test_connection_refused_gets_502(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
        probe.close()  # nobody listens on this port now
        response, _ = self.fetch("/", host=f"127.0.0.1:{free_port}")
        self.assertEqual(response.status, 502)

    def test_slow_destination_gets_504(self):
        proxy = start_proxy(upstream_timeout=0.5)
        self.addCleanup(stop_proxy, proxy)
        response, _ = self.fetch("/hang", proxy=proxy)
        self.assertEqual(response.status, 504)

    def test_oversized_head_gets_431(self):
        proxy = start_proxy(max_header_bytes=256)
        self.addCleanup(stop_proxy, proxy)
        big = b"GET http://a.com/ HTTP/1.1\r\nX-Big: " + b"a" * 1000 + b"\r\n\r\n"
        self.assertTrue(self.raw([big], proxy=proxy).startswith(b"HTTP/1.1 431"))

    def test_client_that_never_sends_gets_408(self):
        proxy = start_proxy(client_timeout=0.3)
        self.addCleanup(stop_proxy, proxy)
        answer = self.raw([], proxy=proxy)
        self.assertTrue(answer.startswith(b"HTTP/1.1 408"))

    def test_many_clients_are_served_in_parallel(self):
        results = []

        def worker():
            response, _ = self.fetch("/slow")
            results.append(response.status)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        started = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.monotonic() - started
        self.assertEqual(results, [200] * 10)
        # Sequential handling would take 10 * 0.3s = 3s.
        self.assertLess(elapsed, 1.8)

    def test_connection_limit_returns_503(self):
        proxy = start_proxy(max_connections=1, client_timeout=3.0)
        self.addCleanup(stop_proxy, proxy)
        hog = socket.create_connection(("127.0.0.1", proxy.port))  # occupies the only slot
        self.addCleanup(hog.close)
        time.sleep(0.2)
        answer = self.raw([b"GET http://a.com/ HTTP/1.1\r\n\r\n"], proxy=proxy)
        self.assertTrue(answer.startswith(b"HTTP/1.1 503"))

    def test_unauthorized_client_is_dropped(self):
        proxy = start_proxy(allowed_clients=set())
        self.addCleanup(stop_proxy, proxy)
        # The proxy hangs up without answering. Depending on timing the client
        # sees a clean close (b"") or a TCP reset; both mean "dropped".
        try:
            answer = self.raw([b"GET http://a.com/ HTTP/1.1\r\n\r\n"], proxy=proxy)
        except ConnectionResetError:
            answer = b""
        self.assertEqual(answer, b"")


# ---------------------------------------------------------------------------
# Security / validation
# ---------------------------------------------------------------------------
class SecurityTests(ProxyTestCase):
    def test_disallowed_port_gets_403(self):
        proxy = start_proxy(insecure_testing=False)
        self.addCleanup(stop_proxy, proxy)
        response, _ = self.fetch("/cacheable", proxy=proxy)
        self.assertEqual(response.status, 403)

    def test_loopback_destination_gets_403_even_on_allowed_port(self):
        proxy = start_proxy(insecure_testing=False, allowed_http_ports={self.origin_port})
        self.addCleanup(stop_proxy, proxy)
        response, body = self.fetch("/cacheable", proxy=proxy)
        self.assertEqual(response.status, 403)
        self.assertIn(b"non-public", body)
        self.assertEqual(self.origin.hits, {})  # the origin was never contacted

    def test_blocked_domain_gets_403(self):
        proxy = start_proxy(blocked_domains={"blocked.test"})
        self.addCleanup(stop_proxy, proxy)
        for host in ("blocked.test", "ads.blocked.test"):
            with self.subTest(host=host):
                response, _ = self.fetch("/", host=host, proxy=proxy)
                self.assertEqual(response.status, 403)


# ---------------------------------------------------------------------------
# STAGE 5 - CONNECT tunnel
# ---------------------------------------------------------------------------
class ConnectTests(ProxyTestCase):
    def test_tunnel_relays_bytes_in_both_directions(self):
        echo = EchoServer()
        self.addCleanup(echo.close)
        sock = socket.create_connection(("127.0.0.1", self.proxy.port), timeout=5)
        self.addCleanup(sock.close)
        sock.sendall(f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        reply = b""
        while b"\r\n\r\n" not in reply:
            reply += sock.recv(1024)
        self.assertTrue(reply.startswith(b"HTTP/1.1 200"))
        sock.sendall(b"ping through the tunnel")
        self.assertEqual(sock.recv(1024), b"ping through the tunnel")

    def test_connect_to_disallowed_port_gets_403(self):
        proxy = start_proxy(insecure_testing=False)
        self.addCleanup(stop_proxy, proxy)
        answer = self.raw([b"CONNECT example.com:25 HTTP/1.1\r\nHost: example.com:25\r\n\r\n"], proxy=proxy)
        self.assertTrue(answer.startswith(b"HTTP/1.1 403"))


# ---------------------------------------------------------------------------
# STAGE 6 - cache
# ---------------------------------------------------------------------------
class CacheTests(ProxyTestCase):
    def hits(self, path):
        return self.origin.hits.get(path, 0)

    def test_second_request_is_a_cache_hit(self):
        first, body1 = self.fetch("/cacheable")
        second, body2 = self.fetch("/cacheable")
        self.assertEqual(first.getheader("X-Cache"), "MISS")
        self.assertEqual(second.getheader("X-Cache"), "HIT")
        self.assertIsNotNone(second.getheader("Age"))
        self.assertEqual(body1, body2)
        self.assertEqual(self.hits("/cacheable"), 1)

    def test_query_string_is_part_of_the_key(self):
        self.fetch("/cacheable?a=1")
        response, _ = self.fetch("/cacheable?a=2")
        self.assertEqual(response.getheader("X-Cache"), "MISS")

    def test_no_store_is_never_cached(self):
        self.fetch("/nostore")
        response, _ = self.fetch("/nostore")
        self.assertEqual(response.getheader("X-Cache"), "MISS")
        self.assertEqual(self.hits("/nostore"), 2)

    def test_set_cookie_responses_are_not_cached(self):
        self.fetch("/cookie")
        self.fetch("/cookie")
        self.assertEqual(self.hits("/cookie"), 2)

    def test_responses_without_freshness_info_are_not_cached(self):
        self.fetch("/missing")
        self.fetch("/missing")
        self.assertEqual(self.hits("/missing"), 2)

    def test_default_ttl_applies_when_configured(self):
        proxy = start_proxy(cache_default_ttl=30)
        self.addCleanup(stop_proxy, proxy)
        self.fetch("/missing", proxy=proxy)
        response, body = self.fetch("/missing", proxy=proxy)
        self.assertEqual((response.status, response.getheader("X-Cache"), body), (404, "HIT", b"nope"))

    def test_entry_expires_after_its_ttl(self):
        self.fetch("/short")
        self.assertEqual(self.fetch("/short")[0].getheader("X-Cache"), "HIT")
        time.sleep(1.2)
        self.assertEqual(self.fetch("/short")[0].getheader("X-Cache"), "MISS")
        self.assertEqual(self.hits("/short"), 2)

    def test_client_no_cache_bypasses_the_cache(self):
        self.fetch("/cacheable")
        response, _ = self.fetch("/cacheable", headers={"Cache-Control": "no-cache"})
        self.assertEqual(response.getheader("X-Cache"), "MISS")
        self.assertEqual(self.hits("/cacheable"), 2)

    def test_post_is_never_cached(self):
        self.fetch("/echo", method="POST", body=b"x")
        self.fetch("/echo", method="POST", body=b"x")
        self.assertEqual(self.hits("/echo"), 2)

    def test_chunked_response_is_cached_and_replayed(self):
        first, body1 = self.fetch("/chunked")
        second, body2 = self.fetch("/chunked")
        self.assertEqual(body1, b"hello world")
        self.assertEqual(second.getheader("X-Cache"), "HIT")
        self.assertEqual(body2, b"hello world")
        self.assertEqual(self.hits("/chunked"), 1)

    def test_cache_can_be_disabled(self):
        proxy = start_proxy(cache_enabled=False)
        self.addCleanup(stop_proxy, proxy)
        self.fetch("/cacheable", proxy=proxy)
        response, _ = self.fetch("/cacheable", proxy=proxy)
        self.assertIsNone(response.getheader("X-Cache"))
        self.assertEqual(self.hits("/cacheable"), 2)

    def test_lru_eviction(self):
        proxy = start_proxy(cache_max_entries=2)
        self.addCleanup(stop_proxy, proxy)
        for name in ("a", "b", "c"):
            self.fetch(f"/cacheable?{name}", proxy=proxy)
        # "a" was the least recently used entry and must have been evicted.
        self.assertEqual(self.fetch("/cacheable?a", proxy=proxy)[0].getheader("X-Cache"), "MISS")

    def test_statistics(self):
        self.fetch("/cacheable")
        self.fetch("/cacheable")
        stats = self.proxy.stats.snapshot()
        self.assertEqual((stats["cache_hits"], stats["cache_misses"], stats["cache_stored"]), (1, 1, 1))


class CachePolicyTests(unittest.TestCase):
    config = Config()
    now = 1_700_000_000.0

    def lifetime(self, headers, status=200, auth=False):
        return compute_lifetime(status, Headers(headers), self.config, self.now, auth)

    def test_max_age(self):
        self.assertEqual(self.lifetime([("Cache-Control", "max-age=60")]), (60.0, 0))

    def test_s_maxage_wins_over_max_age(self):
        self.assertEqual(self.lifetime([("Cache-Control", "max-age=60, s-maxage=10")]), (10.0, 0))

    def test_age_header_reduces_remaining_freshness(self):
        self.assertEqual(self.lifetime([("Cache-Control", "max-age=60"), ("Age", "20")]), (40.0, 20))

    def test_expires_minus_date(self):
        headers = [
            ("Date", "Tue, 14 Nov 2023 22:13:20 GMT"),
            ("Expires", "Tue, 14 Nov 2023 22:14:20 GMT"),
        ]
        self.assertEqual(self.lifetime(headers), (60.0, 0))

    def test_invalid_expires_means_not_cacheable(self):
        self.assertIsNone(self.lifetime([("Expires", "0")]))

    def test_max_age_has_priority_over_expires(self):
        headers = [("Cache-Control", "max-age=5"), ("Expires", "Tue, 14 Nov 2033 22:14:20 GMT")]
        self.assertEqual(self.lifetime(headers), (5.0, 0))

    def test_lifetime_is_capped(self):
        remaining, _ = self.lifetime([("Cache-Control", "max-age=999999")])
        self.assertEqual(remaining, float(self.config.cache_max_ttl))

    def test_forbidden_directives(self):
        for value in ("no-store", "no-cache", "private, max-age=60", "max-age=0"):
            with self.subTest(value=value):
                self.assertIsNone(self.lifetime([("Cache-Control", value)]))

    def test_cookies_vary_and_errors(self):
        base = ("Cache-Control", "max-age=60")
        self.assertIsNone(self.lifetime([base, ("Set-Cookie", "a=b")]))
        self.assertIsNone(self.lifetime([base, ("Vary", "Accept-Encoding")]))
        self.assertIsNone(self.lifetime([base], status=500))

    def test_authorization_requires_public(self):
        self.assertIsNone(self.lifetime([("Cache-Control", "max-age=60")], auth=True))
        self.assertIsNotNone(self.lifetime([("Cache-Control", "public, max-age=60")], auth=True))


if __name__ == "__main__":
    unittest.main()
