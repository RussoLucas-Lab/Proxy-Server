"""HTTP/1.x message reading, parsing and serialization.

STAGE 3 - first implementation: this module turns raw TCP bytes into
structured objects (and back). It knows nothing about sockets' lifecycle or
caching; it only understands the HTTP text format.

Reminder of the format (CRLF = "\\r\\n"):

    GET http://example.com/index.html HTTP/1.1      <- request line
    Host: example.com                               <- headers
    User-Agent: curl/8.9.1
                                                    <- blank line = end of head
    (optional body)
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from .errors import BadGateway, BadRequest, NotImplementedFeature

HEADERS_END = b"\r\n\r\n"
RECV_SIZE = 8192

# Hop-by-hop headers only make sense for ONE connection (client<->proxy or
# proxy<->server). A proxy must not blindly forward them to the next hop.
# "expect" is dropped as well so the server never answers "100 Continue",
# which this simple proxy does not relay.
REQUEST_STRIP_HEADERS = (
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
    "expect",
)
# For responses we keep Transfer-Encoding: we relay the body bytes untouched,
# so the client must still know the body is chunked.
RESPONSE_STRIP_HEADERS = ("connection", "proxy-connection", "keep-alive")


class ConnectionClosedEarly(Exception):
    """The peer closed the connection before a complete message head arrived."""

    def __init__(self, received: int) -> None:
        super().__init__(f"connection closed after {received} bytes")
        self.received = received


class HeadTooLarge(Exception):
    """The request/response head exceeded the configured size limit."""


# --------------------------------------------------------------------------
# Headers container
# --------------------------------------------------------------------------
class Headers:
    """Ordered, case-insensitive collection of HTTP headers.

    Header names are case-insensitive in HTTP ("Host" == "host"), and the same
    name may appear several times (e.g. Set-Cookie), so we keep a list of
    (name, value) pairs instead of a plain dict.
    """

    def __init__(self, items: Optional[Iterable[Tuple[str, str]]] = None) -> None:
        self._items: List[Tuple[str, str]] = list(items or [])

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        name = name.lower()
        for key, value in self._items:
            if key.lower() == name:
                return value
        return default

    def get_all(self, name: str) -> List[str]:
        name = name.lower()
        return [value for key, value in self._items if key.lower() == name]

    def has(self, name: str) -> bool:
        return self.get(name) is not None

    def add(self, name: str, value: str) -> None:
        self._items.append((name, value))

    def remove(self, *names: str) -> None:
        lowered = {n.lower() for n in names}
        self._items = [(k, v) for k, v in self._items if k.lower() not in lowered]

    def items(self) -> List[Tuple[str, str]]:
        return list(self._items)

    def copy(self) -> "Headers":
        return Headers(self._items)


# --------------------------------------------------------------------------
# Reading from a socket
# --------------------------------------------------------------------------
def read_head(sock: socket.socket, max_bytes: int) -> Tuple[bytes, bytes]:
    """Read from `sock` until the blank line that ends the HTTP head.

    TCP is a byte stream: one recv() may return half a header, or the whole
    head plus the beginning of the body. So we accumulate bytes in a buffer
    and keep reading until we see b"\\r\\n\\r\\n".

    Returns (head, rest):
      head - everything before the blank line (without the final CRLFCRLF)
      rest - bytes that arrived AFTER the head (start of the body, etc.).
             They must not be thrown away.
    """
    buffer = bytearray()
    while True:
        chunk = sock.recv(RECV_SIZE)
        if not chunk:
            raise ConnectionClosedEarly(len(buffer))

        # The 4-byte delimiter may be split across two recv() calls, so start
        # searching a few bytes before the newly received data.
        search_from = max(0, len(buffer) - (len(HEADERS_END) - 1))
        buffer += chunk
        end = buffer.find(HEADERS_END, search_from)
        if end != -1:
            if end > max_bytes:
                raise HeadTooLarge()
            return bytes(buffer[:end]), bytes(buffer[end + len(HEADERS_END):])
        if len(buffer) > max_bytes:
            raise HeadTooLarge()


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
def parse_headers(lines: Iterable[str]) -> Headers:
    """Turn "Name: value" lines into a Headers object."""
    headers = Headers()
    for line in lines:
        if not line:
            continue
        if line[0] in " \t":
            raise BadRequest("Obsolete header line folding is not supported")
        name, sep, value = line.partition(":")
        # A space before the colon ("Host : x") is a classic request
        # smuggling trick, so we reject it instead of "fixing" it.
        if not sep or not name or name != name.strip():
            raise BadRequest(f"Malformed header line: {line[:60]!r}")
        headers.add(name, value.strip(" \t"))
    return headers


@dataclass
class Request:
    method: str
    target: str        # exactly what the client wrote after the method
    version: str
    headers: Headers
    host: str          # destination host (lowercase, no brackets)
    port: int          # destination port
    path: str          # path + query, e.g. "/index.html?x=1" (empty for CONNECT)

    @property
    def is_connect(self) -> bool:
        return self.method == "CONNECT"

    def body_length(self) -> int:
        """Number of body bytes announced by the client (0 if none)."""
        if self.headers.has("transfer-encoding"):
            raise NotImplementedFeature("Chunked request bodies are not supported")
        values = {v.strip() for v in self.headers.get_all("content-length")}
        if not values:
            return 0
        # Two different Content-Length values is another smuggling vector.
        if len(values) > 1:
            raise BadRequest("Conflicting Content-Length headers")
        value = values.pop()
        if not (value.isascii() and value.isdigit()):
            raise BadRequest("Invalid Content-Length")
        return int(value)


def _parse_authority(target: str) -> Tuple[str, int]:
    """Parse the "host:port" target of a CONNECT request."""
    if target.startswith("["):  # IPv6 literal such as [2001:db8::1]:443
        end = target.find("]")
        host = target[1:end] if end != -1 else ""
        rest = target[end + 1:] if end != -1 else ""
        port_text = rest[1:] if rest.startswith(":") else ""
    else:
        host, sep, port_text = target.rpartition(":")
        if not sep:
            host, port_text = "", ""
    if not host or not port_text.isdigit():
        raise BadRequest("CONNECT target must look like host:port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise BadRequest("Port out of range")
    return host.lower(), port


def _parse_absolute_url(target: str) -> Tuple[str, int, str]:
    """Parse "http://host[:port]/path?query" into (host, port, path)."""
    if target.startswith("/"):
        raise BadRequest(
            "This is a forward proxy: the request target must be an absolute URL"
        )
    try:
        parts = urlsplit(target)
        port = parts.port or 80
    except ValueError:
        raise BadRequest("Invalid URL")
    scheme = parts.scheme.lower()
    if scheme == "https":
        raise BadRequest("Use the CONNECT method for HTTPS")
    if scheme != "http":
        raise BadRequest(f"Unsupported URL scheme: {parts.scheme!r}")
    if not parts.hostname:
        raise BadRequest("URL has no host")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.hostname, port, path


def parse_request(head: bytes) -> Request:
    """Parse the head (request line + headers) sent by a client."""
    # latin-1 maps every byte to a character, so decoding never fails and
    # re-encoding gives back the exact same bytes.
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise BadRequest("Malformed request line")
    method, target, version = parts
    if not method.isalpha() or not method.isupper():
        raise BadRequest("Invalid method")
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        raise BadRequest("Unsupported HTTP version")

    headers = parse_headers(lines[1:])

    if method == "CONNECT":
        host, port = _parse_authority(target)
        path = ""
    else:
        host, port, path = _parse_absolute_url(target)
    return Request(method, target, version, headers, host, port, path)


# --------------------------------------------------------------------------
# Building what we send to the destination server
# --------------------------------------------------------------------------
def format_host_header(host: str, port: int) -> str:
    if ":" in host:  # IPv6 literal needs brackets
        host = f"[{host}]"
    return host if port == 80 else f"{host}:{port}"


def build_upstream_request(request: Request) -> bytes:
    """Rewrite the client's request for the destination server.

    1. The request line changes from absolute-form (full URL, meant for a
       proxy) to origin-form (just the path, meant for the origin server).
    2. Host is rebuilt from the URL we actually validated, instead of
       trusting whatever the client wrote.
    3. Hop-by-hop headers are removed.
    4. "Connection: close" tells the server to close the connection after
       the response. That is how the proxy knows the response is finished
       when no Content-Length is present.
    """
    headers = request.headers.copy()
    headers.remove("host", *REQUEST_STRIP_HEADERS)
    lines = [
        f"{request.method} {request.path} HTTP/1.1",
        f"Host: {format_host_header(request.host, request.port)}",
    ]
    lines.extend(f"{name}: {value}" for name, value in headers.items())
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


# --------------------------------------------------------------------------
# Responses
# --------------------------------------------------------------------------
@dataclass
class ResponseHead:
    status: int
    reason: str
    headers: Headers


def parse_response_head(head: bytes) -> ResponseHead:
    """Parse the status line + headers sent by the destination server."""
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise BadGateway("The destination sent an invalid response")
    try:
        headers = parse_headers(lines[1:])
    except BadRequest:
        raise BadGateway("The destination sent malformed headers")
    reason = parts[2] if len(parts) == 3 else ""
    return ResponseHead(int(parts[1]), reason, headers)


def serialize_response_head(
    status: int,
    reason: str,
    headers: Headers,
    extra: Iterable[Tuple[str, str]] = (),
) -> bytes:
    """Build the response head we send to the client.

    Hop-by-hop headers are removed, `extra` headers (e.g. X-Cache) are added,
    and we announce "Connection: close" because this proxy closes every
    client connection after one exchange.
    """
    clean = headers.copy()
    clean.remove(*RESPONSE_STRIP_HEADERS)
    lines = [f"HTTP/1.1 {status} {reason}".rstrip()]
    lines.extend(f"{name}: {value}" for name, value in clean.items())
    lines.extend(f"{name}: {value}" for name, value in extra)
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
