"""The proxy server: listener, per-client handler, relay, CONNECT tunnel.

Flow for a plain HTTP request (matches the architecture diagram):

    client --(TCP #1)--> [listener] -> [parser] -> [validation]
                                                       |
                         [cache lookup] <--------------+
                                |miss
                                v
                         [connector + relay] --(TCP #2)--> destination server

The proxy always holds TWO independent TCP connections per request: one with
the client and one with the destination. Everything it does is move bytes
between them.
"""

from __future__ import annotations

import logging
import os
import select
import socket
import threading
import time
from typing import List, Optional

from .cache import (
    STRIPPED_WHEN_STORING,
    Cache,
    CacheEntry,
    compute_lifetime,
    request_allows_cache_lookup,
    request_forbids_storing,
)
from .config import Config
from .errors import (
    BadGateway,
    BadRequest,
    GatewayTimeout,
    HeaderFieldsTooLarge,
    PayloadTooLarge,
    ProxyError,
    RequestTimeout,
    ServiceUnavailable,
)
from .http_parser import (
    RECV_SIZE,
    ConnectionClosedEarly,
    HeadTooLarge,
    Headers,
    Request,
    ResponseHead,
    build_upstream_request,
    parse_request,
    parse_response_head,
    read_head,
    serialize_response_head,
)
from .stats import Stats
from .validator import Address, DestinationValidator

log = logging.getLogger("proxy")


class ProxyServer:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.stats = Stats()
        self.cache = Cache(config)
        self.validator = DestinationValidator(config)
        # STAGE 4 / 7 - limit simultaneous clients. Each client takes one slot
        # and gives it back when its connection is closed.
        self._slots = threading.BoundedSemaphore(config.max_connections)
        self._listener: Optional[socket.socket] = None
        self._stop = threading.Event()

    # ======================================================================
    # STAGE 3 - listening socket and accept loop
    # ======================================================================
    def bind(self) -> None:
        """Create the listening socket (socket -> bind -> listen)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # SO_REUSEADDR lets us restart quickly on Linux/macOS. On Windows it
        # has a different (unsafe) meaning, so we do not set it there.
        if os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.host, self.config.port))
        sock.listen(self.config.backlog)
        # accept() with a timeout, so the loop can notice Ctrl+C / shutdown().
        # (On Windows a blocking accept() cannot be interrupted by Ctrl+C.)
        sock.settimeout(0.2)
        self._listener = sock

    @property
    def port(self) -> int:
        """The real listening port (useful when configured with port 0)."""
        assert self._listener is not None, "call bind() first"
        return self._listener.getsockname()[1]

    def serve_forever(self) -> None:
        if self._listener is None:
            self.bind()
        listener = self._listener
        assert listener is not None
        log.info("Proxy listening on %s:%d", self.config.host, self.port)
        try:
            while not self._stop.is_set():
                try:
                    client_sock, client_addr = listener.accept()
                except socket.timeout:
                    continue  # nothing arrived; check the stop flag again
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                self._dispatch(client_sock, client_addr)
        except KeyboardInterrupt:
            log.info("Shutting down (Ctrl+C)")
        finally:
            listener.close()

    def shutdown(self) -> None:
        self._stop.set()

    # ======================================================================
    # STAGE 4 - one thread per client, with a connection limit
    # ======================================================================
    def _dispatch(self, client_sock: socket.socket, client_addr: tuple) -> None:
        ip = client_addr[0]

        # Security: refuse clients that are not on the allow list.
        if ip not in self.config.allowed_clients:
            log.warning("Rejected connection from unauthorized client %s", ip)
            self.stats.incr("connections_rejected")
            client_sock.close()
            return

        # Overload protection: if every slot is taken, say so and hang up.
        if not self._slots.acquire(blocking=False):
            log.warning("Too many connections; rejecting %s", ip)
            self.stats.incr("connections_rejected")
            # Answering can take a moment (see _send_error), so do it in a
            # short-lived thread to keep the accept loop responsive.
            threading.Thread(
                target=self._reject_busy, args=(client_sock,), daemon=True
            ).start()
            return

        self.stats.incr("connections_accepted")
        self.stats.incr("active_connections")
        thread = threading.Thread(
            target=self._client_thread, args=(client_sock, client_addr), daemon=True
        )
        thread.start()

    def _reject_busy(self, client: socket.socket) -> None:
        try:
            self._send_error(client, ServiceUnavailable("The proxy is busy, try again later"))
        finally:
            client.close()

    def _client_thread(self, client: socket.socket, client_addr: tuple) -> None:
        try:
            self._handle_client(client, client_addr)
        finally:
            # Always close the socket and free the slot, even after errors.
            # Forgetting this would leak file descriptors (resource leak).
            try:
                client.close()
            finally:
                self.stats.incr("active_connections", -1)
                self._slots.release()

    def _handle_client(self, client: socket.socket, client_addr: tuple) -> None:
        started = time.monotonic()
        client.settimeout(self.config.client_timeout)
        request: Optional[Request] = None
        status = 0
        try:
            head, leftover = self._read_request_head(client)
            request = parse_request(head)
            if request.is_connect:
                status = self._handle_connect(client, request, leftover)
            else:
                status = self._handle_http(client, request, leftover)
        except ConnectionClosedEarly:
            log.debug("%s closed the connection without sending a request", client_addr[0])
            return
        except ProxyError as exc:
            status = exc.status
            self.stats.incr(f"errors_{exc.status}")
            self._send_error(client, exc)
        except socket.timeout:
            log.warning("Timeout while talking to %s", client_addr[0])
        except OSError as exc:
            # Resets, broken pipes... Nothing to answer; just clean up.
            log.debug("Connection error with %s: %s", client_addr[0], exc)
        except Exception:  # noqa: BLE001 - last line of defence for a thread
            log.exception("Unexpected error while handling %s", client_addr[0])
            status = 500
            self.stats.incr("errors_500")
            self._send_error(client, ProxyError("Unexpected proxy error"))
        finally:
            elapsed_ms = (time.monotonic() - started) * 1000
            if request is not None:
                log.info(
                    '%s "%s %s" %s %.0fms',
                    client_addr[0], request.method, request.target, status or "-", elapsed_ms,
                )
            elif status:
                log.info('%s "-" %s %.0fms', client_addr[0], status, elapsed_ms)

    def _read_request_head(self, client: socket.socket):
        try:
            return read_head(client, self.config.max_header_bytes)
        except HeadTooLarge:
            raise HeaderFieldsTooLarge("Request head is too large")
        except ConnectionClosedEarly as exc:
            if exc.received == 0:
                raise  # client connected and left: not worth an error page
            raise BadRequest("Incomplete request")
        except socket.timeout:
            raise RequestTimeout("Timed out waiting for the request")

    # ======================================================================
    # STAGE 3 + 6 - plain HTTP: validate, cache lookup, connect, relay
    # ======================================================================
    def _handle_http(self, client: socket.socket, request: Request, leftover: bytes) -> int:
        cfg = self.config
        self.stats.incr("http_requests")

        body_length = request.body_length()
        if body_length > cfg.max_body_bytes:
            raise PayloadTooLarge("Request body is too large")

        # Cheap policy checks first (blocked domain, allowed port).
        self.validator.check_policy(request.host, request.port, is_connect=False)

        # STAGE 6 - try the cache before touching the network.
        use_cache = cfg.cache_enabled and request.method == "GET"
        cache_key = Cache.make_key(request.host, request.port, request.path) if use_cache else None
        if use_cache and request_allows_cache_lookup(request):
            entry = self.cache.get(cache_key)  # type: ignore[arg-type]
            if entry is not None:
                return self._serve_from_cache(client, entry)

        # Cache miss (or cache not applicable): go to the destination.
        if use_cache:
            self.stats.incr("cache_misses")
        addresses = self.validator.resolve(request.host, request.port)
        upstream = self._connect_upstream(addresses)
        try:
            try:
                upstream.sendall(build_upstream_request(request))
                self._forward_request_body(client, upstream, leftover, body_length)
                head, rest = self._read_upstream_head(upstream)
            except socket.timeout:
                raise GatewayTimeout("The destination did not answer in time")
            except OSError as exc:
                raise BadGateway(f"Error talking to the destination: {exc}")

            response = parse_response_head(head)
            return self._relay_response(
                client, upstream, request, response, rest,
                cache_key=cache_key if use_cache else None,
            )
        finally:
            upstream.close()

    def _connect_upstream(self, addresses: List[Address]) -> socket.socket:
        """Open TCP connection #2, trying each validated address in turn."""
        last_error: Optional[BaseException] = None
        for family, sockaddr in addresses:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.config.upstream_timeout)
            try:
                sock.connect(sockaddr)
                return sock
            except OSError as exc:  # includes socket.timeout
                last_error = exc
                sock.close()
        if isinstance(last_error, socket.timeout):
            raise GatewayTimeout("Timed out connecting to the destination")
        raise BadGateway(f"Could not connect to the destination: {last_error}")

    def _forward_request_body(
        self, client: socket.socket, upstream: socket.socket, leftover: bytes, length: int
    ) -> None:
        """Copy exactly `length` body bytes from client to destination."""
        if length == 0:
            return
        # Part of the body may already be in `leftover` (it arrived together
        # with the headers). Send that first, then read the rest.
        chunk = leftover[:length]
        if chunk:
            upstream.sendall(chunk)
        remaining = length - len(chunk)
        while remaining > 0:
            try:
                data = client.recv(min(RECV_SIZE, remaining))
            except socket.timeout:
                raise RequestTimeout("Timed out waiting for the request body")
            if not data:
                raise BadRequest("Client closed the connection before sending the full body")
            upstream.sendall(data)
            remaining -= len(data)

    def _read_upstream_head(self, upstream: socket.socket):
        try:
            return read_head(upstream, self.config.max_header_bytes)
        except HeadTooLarge:
            raise BadGateway("The destination sent a response head that is too large")
        except ConnectionClosedEarly:
            raise BadGateway("The destination closed the connection without answering")

    @staticmethod
    def _expected_body_length(request: Request, response: ResponseHead) -> Optional[int]:
        """How many body bytes follow the head, or None if "until close"."""
        if request.method == "HEAD" or response.status in (204, 304) or 100 <= response.status < 200:
            return 0
        if response.headers.has("transfer-encoding"):
            return None  # chunked: we relay the raw bytes until the server closes
        length = (response.headers.get("content-length") or "").strip()
        if length.isascii() and length.isdigit():
            return int(length)
        return None

    def _relay_response(
        self,
        client: socket.socket,
        upstream: socket.socket,
        request: Request,
        response: ResponseHead,
        first_body_bytes: bytes,
        cache_key: Optional[str],
    ) -> int:
        """Send the response to the client, optionally storing it in the cache."""
        cfg = self.config

        # STAGE 6 - decide up front whether this response is storable.
        freshness = None
        if cache_key is not None and not request_forbids_storing(request):
            freshness = compute_lifetime(
                response.status, response.headers, cfg, time.time(),
                request_has_authorization=request.headers.has("authorization"),
            )

        extra = [("X-Cache", "MISS")] if cache_key is not None else []
        head_bytes = serialize_response_head(response.status, response.reason, response.headers, extra)
        client.sendall(head_bytes)
        sent = len(head_bytes)

        expected = self._expected_body_length(request, response)
        collect = freshness is not None and (
            expected is None or expected <= cfg.cache_max_object_bytes
        )
        parts: List[bytes] = []
        collected = 0
        received = 0
        complete = False
        stored = False

        def store_if_complete(is_complete: bool) -> None:
            """STAGE 6 - store the response, but only if we got all of it."""
            nonlocal stored
            if stored or not (is_complete and collect and freshness is not None and cache_key is not None):
                return
            stored = True
            body = b"".join(parts)
            chunked = response.headers.has("transfer-encoding")
            if not chunked or body.endswith(b"0\r\n\r\n"):  # chunked must end cleanly
                self._store(cache_key, response, body, freshness)

        # From here on the client already got a status line, so we can no
        # longer send an error page. Problems are logged and the connections
        # are closed (by the caller's `finally` blocks).
        try:
            data = first_body_bytes
            while True:
                if data:
                    if expected is not None and received + len(data) > expected:
                        data = data[: expected - received]  # ignore extra bytes
                    received += len(data)
                    sent += len(data)
                    if collect:
                        collected += len(data)
                        if collected > cfg.cache_max_object_bytes:
                            collect = False  # too big to cache
                            parts.clear()
                        else:
                            parts.append(data)
                    if expected is not None and received >= expected:
                        # Store BEFORE sending the last bytes: once the client
                        # has the full response it may immediately ask again,
                        # and that second request must already find the entry.
                        store_if_complete(True)
                    client.sendall(data)
                if expected is not None and received >= expected:
                    complete = True  # Content-Length satisfied
                    break
                data = upstream.recv(RECV_SIZE)
                if not data:
                    # Connection closed by the server: that is the end of a
                    # response with no length information.
                    complete = expected is None
                    break
        except socket.timeout:
            log.warning("Timeout while relaying %s", request.target)
        except OSError as exc:
            log.debug("Relay interrupted for %s: %s", request.target, exc)

        self.stats.incr("bytes_to_client", sent)
        # Responses without Content-Length end when the server closes, which
        # is only known here (the client sees the end when WE close, later).
        store_if_complete(complete)
        return response.status

    def _store(self, key: str, response: ResponseHead, body: bytes, freshness) -> None:
        remaining, initial_age = freshness
        kept = Headers(response.headers.items())
        kept.remove(*STRIPPED_WHEN_STORING)
        now = time.monotonic()
        self.cache.put(
            key,
            CacheEntry(
                status=response.status,
                reason=response.reason,
                headers=kept.items(),
                body=body,
                stored_at=now,
                initial_age=initial_age,
                expires_at=now + remaining,
            ),
        )
        self.stats.incr("cache_stored")
        log.debug("Stored %s in cache for %.0fs", key, remaining)

    def _serve_from_cache(self, client: socket.socket, entry: CacheEntry) -> int:
        """STAGE 6 - answer a request without contacting the destination."""
        now = time.monotonic()
        extra = [("Age", str(int(entry.age(now)))), ("X-Cache", "HIT")]
        head = serialize_response_head(entry.status, entry.reason, Headers(entry.headers), extra)
        self.stats.incr("cache_hits")
        self.stats.incr("bytes_to_client", len(head) + len(entry.body))
        client.sendall(head + entry.body)
        return entry.status

    # ======================================================================
    # STAGE 5 - HTTPS through a CONNECT tunnel
    # ======================================================================
    def _handle_connect(self, client: socket.socket, request: Request, leftover: bytes) -> int:
        """Open a blind TCP tunnel between the client and the destination.

        The client sends "CONNECT example.com:443 HTTP/1.1". After we answer
        "200", the client starts a TLS handshake with the destination THROUGH
        us. We never see the plaintext: we only copy encrypted bytes in both
        directions. We do not (and must not) decrypt anything.
        """
        self.stats.incr("connect_tunnels")
        self.validator.check_policy(request.host, request.port, is_connect=True)
        addresses = self.validator.resolve(request.host, request.port)
        upstream = self._connect_upstream(addresses)
        try:
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if leftover:  # bytes the client sent right after the CONNECT head
                upstream.sendall(leftover)
            self._tunnel(client, upstream)
        finally:
            upstream.close()
        return 200

    def _tunnel(self, client: socket.socket, upstream: socket.socket) -> None:
        """Copy bytes in both directions until either side closes or idles out.

        select() waits until at least one socket has data ready, so a single
        thread can serve both directions without blocking on the wrong one.

        Simplification: when one side closes we close both. Real proxies
        propagate half-closes (shutdown(SHUT_WR)) so a final response can
        still be delivered.
        """
        idle = self.config.tunnel_idle_timeout
        client.settimeout(idle)
        upstream.settimeout(idle)
        sockets = [client, upstream]
        while True:
            readable, _, broken = select.select(sockets, [], sockets, idle)
            if broken or not readable:
                return  # socket error, or nothing happened for `idle` seconds
            for source in readable:
                target = upstream if source is client else client
                try:
                    data = source.recv(RECV_SIZE)
                    if not data:
                        return  # one side closed
                    target.sendall(data)
                except OSError:
                    return
                self.stats.incr("tunnel_bytes", len(data))

    # ======================================================================
    # STAGE 4 - error responses
    # ======================================================================
    @staticmethod
    def _send_error(client: socket.socket, exc: ProxyError) -> None:
        body = f"{exc.status} {exc.reason}\n{exc.message}\n".encode("utf-8", errors="replace")
        head = (
            f"HTTP/1.1 {exc.status} {exc.reason}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("latin-1")
        try:
            client.settimeout(2)
            client.sendall(head + body)
            ProxyServer._drain(client)
        except OSError:
            pass  # the client is already gone; nothing else to do

    @staticmethod
    def _drain(client: socket.socket) -> None:
        """Close our sending side and read whatever the client still sends.

        If we close a socket that still has UNREAD incoming data, the OS
        answers with a TCP reset (RST) and the client may lose the error page
        we just sent. Sending FIN first (shutdown) and reading the leftovers
        lets the client receive the response normally. The time and byte
        limits stop a malicious client from keeping the thread busy.
        """
        client.shutdown(socket.SHUT_WR)
        client.settimeout(0.5)
        deadline = time.monotonic() + 1.0
        budget = 64 * 1024
        while budget > 0 and time.monotonic() < deadline:
            data = client.recv(RECV_SIZE)
            if not data:
                break
            budget -= len(data)
