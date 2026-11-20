# Caching Proxy

A forward HTTP proxy written from scratch in Python (standard library only),
built stage by stage as a learning project: plain HTTP forwarding, HTTPS
tunneling with `CONNECT`, concurrency, and a response cache.

```
                 TCP connection #1                    TCP connection #2
  client  <------------------------>  [   proxy   ]  <------------------>  destination
 (curl)         HTTP / CONNECT          listener                              server
                                        parser
                                        validation
                                        cache
                                        connector + relay
```

## Run it

```bash
python main.py                      # listens on 127.0.0.1:8000
python main.py --port 9000 --verbose
python main.py --block ads.example.com --cache-default-ttl 60
python main.py --help
```

Try it (on Windows PowerShell use `curl.exe`, because `curl` is an alias of
another command):

```bash
curl.exe -x http://127.0.0.1:8000 http://example.com            # plain HTTP
curl.exe -x http://127.0.0.1:8000 -i http://example.com         # see X-Cache: MISS / HIT
curl.exe -x http://127.0.0.1:8000 https://example.com           # CONNECT tunnel
```

Stop it with `Ctrl+C`; it prints request statistics on exit.

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite starts a tiny origin server and the proxy on localhost, so it needs
no Internet access.

## Where each stage lives

| Stage | Topic | Code |
|-------|-------|------|
| 1-2 | Networking basics, architecture | this README (diagram above) |
| 3 | First implementation: listener, reading the request, parsing, forwarding | `proxy/server.py` (`bind`, `serve_forever`, `_handle_http`), `proxy/http_parser.py` |
| 4 | Connection handling: threads, timeouts, error responses, clean shutdown of sockets | `proxy/server.py` (`_dispatch`, `_client_thread`, `_send_error`, `_drain`), `proxy/errors.py` |
| 5 | HTTPS via `CONNECT` tunnels (no TLS interception) | `proxy/server.py` (`_handle_connect`, `_tunnel`) |
| 6 | Caching: hit/miss, TTL, `Cache-Control`, `Expires` | `proxy/cache.py`, `proxy/server.py` (`_relay_response`, `_serve_from_cache`) |
| 7 | Extras: logging, statistics, domain filtering, connection limits | `proxy/stats.py`, `proxy/validator.py`, `proxy/config.py` |

Security rules (section 7 of the brief) are enforced in `proxy/validator.py`
and `_dispatch`: localhost-only by default, client allow-list, allowed
destination ports, and destinations that resolve to private/loopback/link-local
addresses are refused (the proxy connects to the *validated* IP, never to a
second DNS answer).

## Design decisions worth knowing

* **Threads, one per client** (bounded by `max_connections`). Simple to reason
  about; `asyncio` would scale better and is a natural next exercise.
* **One request per connection.** The proxy sends `Connection: close` upstream
  and closes the client connection after answering. No keep-alive.
* **Responses are relayed byte for byte** until the server closes (or
  `Content-Length` is reached), so chunked responses work without decoding.
* **The cache is a shared cache**, so it is conservative: it never stores
  `no-store`, `no-cache`, `private`, `Set-Cookie`, `Vary`, or responses to
  requests with `Authorization`.

## Known limitations / ideas to extend

* No cache revalidation (`ETag` / `If-None-Match` -> `304`), no `Vary` support.
* No chunked *request* bodies, no `Upgrade` (WebSocket) over plain HTTP.
* `CONNECT` closes both directions when one side closes (no half-close).
* Not implemented from stage 7: proxy authentication, configuration file.
  A good place for a FastAPI admin API (stats, blocklist, cache purge).
* Do not expose this proxy to the Internet without authentication.
