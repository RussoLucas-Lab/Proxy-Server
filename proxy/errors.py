"""Exceptions that map directly to HTTP error responses.

STAGE 4 - error handling: instead of returning status codes from deep inside
the code, any component raises one of these exceptions. The connection
handler catches them in ONE place and turns them into a proper HTTP response
for the client. This keeps the happy path easy to read.
"""

from __future__ import annotations


class ProxyError(Exception):
    """Base class: carries the HTTP status code to send back to the client."""

    status = 500
    reason = "Internal Server Error"

    def __init__(self, message: str = "") -> None:
        self.message = message or self.reason
        super().__init__(self.message)


class BadRequest(ProxyError):
    status = 400
    reason = "Bad Request"


class Forbidden(ProxyError):
    status = 403
    reason = "Forbidden"


class RequestTimeout(ProxyError):
    status = 408
    reason = "Request Timeout"


class PayloadTooLarge(ProxyError):
    status = 413
    reason = "Payload Too Large"


class HeaderFieldsTooLarge(ProxyError):
    status = 431
    reason = "Request Header Fields Too Large"


class NotImplementedFeature(ProxyError):
    status = 501
    reason = "Not Implemented"


class BadGateway(ProxyError):
    """The destination (upstream) server failed or could not be reached."""

    status = 502
    reason = "Bad Gateway"


class ServiceUnavailable(ProxyError):
    """The proxy itself is overloaded (too many simultaneous connections)."""

    status = 503
    reason = "Service Unavailable"


class GatewayTimeout(ProxyError):
    """The destination server did not answer in time."""

    status = 504
    reason = "Gateway Timeout"
