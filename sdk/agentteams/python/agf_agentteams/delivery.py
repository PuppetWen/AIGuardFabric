"""Telemetry HTTP only. Redirects never forward the collector credential."""
from dataclasses import dataclass
from http.client import HTTPException
import json
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID


@dataclass(frozen=True)
class Delivery:
    code: str
    accepted: int = 0
    deduped: int = 0
    durable: bool | None = None
    retry_after: float = 0


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def send(config, batch, timeout):
    body = json.dumps({"binding_id": config.binding_id, "events": [event for _, event in batch]},
                      ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = Request(config.endpoint, data=body, method="POST", headers={
        "Authorization": "Bearer " + config.collector_key, "Content-Type": "application/json",
        "Accept": "application/json", "User-Agent": "AIGuardFabric-AgentTeams-Python/0.1"})
    try:
        with build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
            if response.status != 200:
                return Delivery("unexpected_status")
            raw = response.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                return Delivery("invalid_ack")
            return validate_ack(config, batch, raw)
    except HTTPError as error:
        try:
            delay = min(60, max(0, float(error.headers.get("Retry-After", "0"))))
        except (ValueError, TypeError, AttributeError):
            delay = 0
        finally:
            error.close()
        return Delivery(f"http_{error.code}", retry_after=delay)
    except (URLError, TimeoutError, OSError, HTTPException):
        return Delivery("network_error")
    except (ValueError, TypeError, UnicodeError):
        return Delivery("invalid_ack")


def validate_ack(config, batch, raw):
    try:
        reply = json.loads(raw)
        if not isinstance(reply, dict):
            return Delivery("invalid_ack")
        # The platform API returns a plain JSON object. Do not accept guessed envelopes.
        received, accepted, deduped = (reply[name] for name in ("received", "accepted", "deduped"))
        scope = str(UUID(reply["scopeId"]))
        if (any(type(value) is not int or value < 0 for value in (received, accepted, deduped))
                or received != len(batch) or accepted + deduped != received
                or type(reply["mocked"]) is not bool or type(reply["durable"]) is not bool
                or reply.get("authorizationStatus") != "unknown"
                or config.expected_scope is not None and scope != config.expected_scope
                or config.expected_mocked is not None and reply["mocked"] != config.expected_mocked):
            return Delivery("invalid_ack")
        return Delivery("ack", accepted, deduped, reply["durable"])
    except (KeyError, ValueError, TypeError, AttributeError, UnicodeError):
        return Delivery("invalid_ack")
