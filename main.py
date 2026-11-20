"""Command-line entry point.

    python main.py                        # listen on 127.0.0.1:8000
    python main.py --port 9000 --verbose
    python main.py --block ads.example.com --block tracker.example.org

Try it (Windows PowerShell: use curl.exe, not curl):

    curl.exe -x http://127.0.0.1:8000 http://example.com
    curl.exe -x http://127.0.0.1:8000 https://example.com     # CONNECT tunnel
"""

from __future__ import annotations

import argparse
import logging
import sys

from proxy.config import Config
from proxy.server import ProxyServer

log = logging.getLogger("proxy")


def parse_args(argv=None) -> argparse.Namespace:
    defaults = Config()
    parser = argparse.ArgumentParser(description="A small forward proxy with a cache.")
    parser.add_argument("--host", default=defaults.host, help="address to listen on (default: %(default)s)")
    parser.add_argument("--port", type=int, default=defaults.port, help="port to listen on (default: %(default)s)")
    parser.add_argument("--client-timeout", type=float, default=defaults.client_timeout)
    parser.add_argument("--upstream-timeout", type=float, default=defaults.upstream_timeout)
    parser.add_argument("--max-connections", type=int, default=defaults.max_connections)
    parser.add_argument("--allow-client", action="append", default=None, metavar="IP",
                        help="client IP allowed to use the proxy (repeatable; default: localhost only)")
    parser.add_argument("--block", action="append", default=[], metavar="DOMAIN",
                        help="refuse this domain and its subdomains (repeatable)")
    parser.add_argument("--no-cache", action="store_true", help="disable the response cache")
    parser.add_argument("--cache-max-entries", type=int, default=defaults.cache_max_entries)
    parser.add_argument("--cache-default-ttl", type=int, default=defaults.cache_default_ttl,
                        help="seconds to cache responses without freshness info (default: 0 = do not)")
    parser.add_argument("--insecure-testing", action="store_true",
                        help="DANGEROUS: allow any port and private/loopback destinations")
    parser.add_argument("--verbose", action="store_true", help="debug logging")
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> Config:
    config = Config(
        host=args.host,
        port=args.port,
        client_timeout=args.client_timeout,
        upstream_timeout=args.upstream_timeout,
        max_connections=args.max_connections,
        cache_enabled=not args.no_cache,
        cache_max_entries=args.cache_max_entries,
        cache_default_ttl=args.cache_default_ttl,
        blocked_domains=set(args.block),
        insecure_testing=args.insecure_testing,
    )
    if args.allow_client:
        config.allowed_clients = set(args.allow_client)
    return config


def main(argv=None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s [%(threadName)s] %(message)s",
    )
    config = build_config(args)

    if config.host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("Listening on %s: make sure --allow-client is restricted!", config.host)
    if config.insecure_testing:
        log.warning("INSECURE TESTING MODE: destination restrictions are disabled")

    server = ProxyServer(config)
    try:
        server.serve_forever()
    finally:
        print()
        print(server.stats.format())
    return 0


if __name__ == "__main__":
    sys.exit(main())
