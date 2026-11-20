"""Central configuration for the proxy.

Every tunable value lives here so the rest of the code never hard-codes
magic numbers. Each group of fields is labelled with the stage that
introduced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Set


@dataclass
class Config:
    # ---- STAGE 3: basic listener ------------------------------------------
    # Listen on localhost only. Binding to 0.0.0.0 would expose the proxy to
    # the whole network, which is how "open proxies" are born.
    host: str = "127.0.0.1"
    port: int = 8000
    # Upper bound for the request line + headers. Without a limit a client
    # could send endless data and exhaust the proxy's memory.
    max_header_bytes: int = 64 * 1024
    # Upper bound for request bodies (POST/PUT) that we are willing to relay.
    max_body_bytes: int = 10 * 1024 * 1024

    # ---- STAGE 4: connection handling -------------------------------------
    # Seconds to wait for the client to send its request.
    client_timeout: float = 15.0
    # Seconds to wait when connecting to / reading from the destination.
    upstream_timeout: float = 15.0
    # A CONNECT tunnel with no traffic in either direction for this long is
    # closed.
    tunnel_idle_timeout: float = 60.0
    # Maximum number of clients served at the same time.
    max_connections: int = 100
    # Size of the OS queue of connections waiting to be accepted.
    backlog: int = 50

    # ---- Security (section 7 of the project brief) -------------------------
    # Only these client IP addresses may use the proxy.
    allowed_clients: Set[str] = field(default_factory=lambda: {"127.0.0.1", "::1"})
    # Destination ports allowed for plain HTTP requests.
    allowed_http_ports: Set[int] = field(default_factory=lambda: {80, 8080})
    # Destination ports allowed for CONNECT tunnels (HTTPS).
    allowed_connect_ports: Set[int] = field(default_factory=lambda: {443})
    # DANGEROUS: disables the port restrictions and the "public addresses
    # only" rule. It exists so tests can talk to servers on localhost.
    insecure_testing: bool = False

    # ---- STAGE 6: caching --------------------------------------------------
    cache_enabled: bool = True
    # Maximum number of cached responses (least recently used are evicted).
    cache_max_entries: int = 256
    # Responses with bigger bodies are never stored.
    cache_max_object_bytes: int = 1024 * 1024
    # Upper bound for any freshness lifetime, in seconds.
    cache_max_ttl: int = 3600
    # Lifetime (seconds) for cacheable responses that carry no explicit
    # freshness information. 0 means "do not cache those".
    cache_default_ttl: int = 0

    # ---- STAGE 7: extras ---------------------------------------------------
    # Domains (and all their subdomains) that the proxy refuses to visit.
    blocked_domains: Set[str] = field(default_factory=set)
