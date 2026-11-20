"""STAGE 6 - HTTP response cache.

Vocabulary:
  * cache hit   - the request is answered from the stored copy.
  * cache miss  - no usable copy, we go to the destination server.
  * TTL         - how long a stored copy stays "fresh" (usable) in seconds.

This is a *shared* cache (it serves several clients), which makes it stricter
than a browser cache about what it may store. The rules here are a simplified
version of RFC 9111:

  * Only GET responses with a cacheable status code are stored.
  * The server must say how long the copy is fresh:
        Cache-Control: s-maxage=N  (wins)  >  max-age=N  >  Expires - Date
  * Never stored: no-store, no-cache, private, responses with Set-Cookie,
    responses with Vary, or responses to requests carrying Authorization.
  * The client can opt out with "Cache-Control: no-cache" / "Pragma: no-cache".

Not implemented (good extensions): revalidation with ETag / Last-Modified
(If-None-Match -> 304), Vary support, heuristic freshness, stale-while-
revalidate.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional, Tuple

from .config import Config
from .http_parser import Headers, Request

CACHEABLE_STATUSES = frozenset({200, 203, 300, 301, 308, 404, 410})

# Headers we do not keep in the stored copy. "Age" is recomputed on every hit
# and the connection headers belong to the original connection only.
STRIPPED_WHEN_STORING = ("age", "connection", "proxy-connection", "keep-alive")


@dataclass
class CacheEntry:
    status: int
    reason: str
    headers: List[Tuple[str, str]]
    body: bytes
    stored_at: float      # time.monotonic() when we stored it
    initial_age: int      # seconds the response had already aged (Age header)
    expires_at: float     # time.monotonic() after which it is stale

    def is_fresh(self, now: float) -> bool:
        return now < self.expires_at

    def age(self, now: float) -> float:
        return self.initial_age + (now - self.stored_at)


class Cache:
    """Thread-safe LRU cache keyed by destination URL."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._entries: "OrderedDict[str, CacheEntry]" = OrderedDict()
        self._lock = threading.Lock()  # many client threads share the cache

    @staticmethod
    def make_key(host: str, port: int, path: str) -> str:
        return f"{host}:{port}{path}"

    def get(self, key: str) -> Optional[CacheEntry]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if not entry.is_fresh(time.monotonic()):
                del self._entries[key]  # expired: drop it
                return None
            self._entries.move_to_end(key)  # mark as recently used
            return entry

    def put(self, key: str, entry: CacheEntry) -> None:
        with self._lock:
            self._entries[key] = entry
            self._entries.move_to_end(key)
            while len(self._entries) > self._config.cache_max_entries:
                self._entries.popitem(last=False)  # evict least recently used

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


# --------------------------------------------------------------------------
# Cache policy: "may we store this?" and "for how long?"
# --------------------------------------------------------------------------
def parse_cache_control(value: str) -> Dict[str, Optional[str]]:
    """"max-age=60, public" -> {"max-age": "60", "public": None}"""
    directives: Dict[str, Optional[str]] = {}
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        name, sep, argument = part.partition("=")
        directives[name.strip().lower()] = argument.strip().strip('"') if sep else None
    return directives


def parse_http_date(value: str) -> Optional[float]:
    """Parse an HTTP date ("Wed, 21 Oct 2026 07:28:00 GMT") to a timestamp."""
    try:
        moment = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _request_directives(request: Request) -> Dict[str, Optional[str]]:
    return parse_cache_control(", ".join(request.headers.get_all("cache-control")))


def request_allows_cache_lookup(request: Request) -> bool:
    """False when the client explicitly asks for a fresh copy."""
    directives = _request_directives(request)
    if "no-cache" in directives or "no-store" in directives:
        return False
    if directives.get("max-age") == "0":
        return False
    pragma = request.headers.get("pragma")
    return not (pragma and "no-cache" in pragma.lower())


def request_forbids_storing(request: Request) -> bool:
    return "no-store" in _request_directives(request)


def compute_lifetime(
    status: int,
    headers: Headers,
    config: Config,
    now_wall: float,
    request_has_authorization: bool,
) -> Optional[Tuple[float, int]]:
    """Decide whether a response may be stored.

    Returns None when it must NOT be stored, otherwise
    (remaining_freshness_seconds, initial_age_seconds).

    Note: `now_wall` is wall-clock time (time.time()) because HTTP dates are
    wall-clock. The cache itself uses time.monotonic() to measure elapsed time.
    """
    if status not in CACHEABLE_STATUSES:
        return None

    directives = parse_cache_control(", ".join(headers.get_all("cache-control")))
    if any(d in directives for d in ("no-store", "no-cache", "private")):
        return None
    # Set-Cookie usually means a per-user response; Vary means the body depends
    # on request headers, which our key does not include. Be conservative.
    if headers.has("set-cookie") or headers.has("vary"):
        return None
    if (
        request_has_authorization
        and "public" not in directives
        and "s-maxage" not in directives
    ):
        return None

    # Freshness lifetime, in order of precedence.
    raw = directives.get("s-maxage") if "s-maxage" in directives else directives.get("max-age")
    if "s-maxage" in directives or "max-age" in directives:
        try:
            lifetime = float(int(raw))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None
    elif headers.has("expires"):
        expires_at = parse_http_date(headers.get("expires") or "")
        if expires_at is None:
            return None  # invalid Expires (e.g. "0") means "already expired"
        date_at = parse_http_date(headers.get("date") or "") or now_wall
        lifetime = expires_at - date_at
    else:
        lifetime = float(config.cache_default_ttl)

    lifetime = min(lifetime, float(config.cache_max_ttl))

    initial_age = 0
    age_header = (headers.get("age") or "").strip()
    if age_header.isascii() and age_header.isdigit():
        initial_age = int(age_header)

    remaining = lifetime - initial_age
    if remaining <= 0:
        return None
    return remaining, initial_age
