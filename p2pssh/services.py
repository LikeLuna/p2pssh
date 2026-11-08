"""Service selection on top of a secure session (owner: Member 1).

RULE: one connection carries exactly ONE service ("chat", "shell" or "file").
Right after the handshake the two sides agree on which one, with two records:

    initiator -> responder :  b"svc:<name>"             (the request)
    responder -> initiator :  b"ok"  or  b"denied:<reason>"

After "ok" the chosen service owns the session (chat.py, shell.py or files.py).
No multiplexing and no message-type bytes are needed.

The responder calls serve_service(); the initiator calls request_service().
The shell is dangerous, so make_authorizer() decides on the HOST whether a peer
may use it: allow_shell must be on AND the peer's key must be trusted.
"""
from .errors import P2PSSHError
from .prompts import clean_text

SERVICE_CHAT = "chat"
SERVICE_SHELL = "shell"
SERVICE_FILE = "file"
KNOWN_SERVICES = (SERVICE_CHAT, SERVICE_SHELL, SERVICE_FILE)

REQUEST_PREFIX = b"svc:"
REPLY_OK = b"ok"
REPLY_DENIED_PREFIX = b"denied:"

MAX_REQUEST_SIZE = 64
MAX_REASON_SIZE = 120


class ServiceError(P2PSSHError):
    """The peer refused, or the service request was malformed."""


async def request_service(session, name: str) -> None:
    """Initiator: ask the peer for a service. Raises ServiceError if it is refused."""
    if name not in KNOWN_SERVICES:
        raise ValueError(f"unknown service: {name!r}")
    await session.send(REQUEST_PREFIX + name.encode("ascii"))
    reply = await session.recv()
    if reply == REPLY_OK:
        return
    if reply.startswith(REPLY_DENIED_PREFIX):
        reason = reply[len(REPLY_DENIED_PREFIX):MAX_REASON_SIZE + len(REPLY_DENIED_PREFIX)]
        shown = clean_text(reason.decode("utf-8", errors="replace"), MAX_REASON_SIZE)
        raise ServiceError(f"peer refused '{name}': {shown}")
    raise ServiceError("unexpected reply from peer")


async def deny_service(session, reason: str) -> None:
    await session.send(REPLY_DENIED_PREFIX + reason.encode("utf-8")[:MAX_REASON_SIZE])


async def accept_service(session) -> None:
    await session.send(REPLY_OK)


async def read_service_request(session) -> str:
    """Responder: read and validate the request. Sends 'denied' and raises if it is bad."""
    data = await session.recv()
    if len(data) > MAX_REQUEST_SIZE or not data.startswith(REQUEST_PREFIX):
        await deny_service(session, "bad request")
        raise ServiceError("malformed service request")
    try:
        name = data[len(REQUEST_PREFIX):].decode("ascii")
    except UnicodeDecodeError:
        await deny_service(session, "bad request")
        raise ServiceError("malformed service request") from None
    if name not in KNOWN_SERVICES:
        await deny_service(session, "unknown service")
        raise ServiceError(f"unknown service requested: {clean_text(name)}")
    return name


async def serve_service(session, handlers: dict, authorize=None) -> str:
    """Responder: read the request, check permission, answer, then run the handler.

    handlers  : {"chat": async fn(session), "shell": ..., "file": ...}
    authorize : optional fn(name) -> None if allowed, else a reason string.
    Returns the service name that ran.
    """
    name = await read_service_request(session)
    handler = handlers.get(name)
    if handler is None:
        await deny_service(session, "service not available")
        raise ServiceError(f"'{name}' is not available on this host")
    reason = authorize(name) if authorize is not None else None
    if reason:
        await deny_service(session, reason)
        raise ServiceError(f"denied '{name}': {reason}")
    await accept_service(session)
    await handler(session)
    return name


def make_authorizer(cfg, trust, peer_fingerprint: str):
    """Host-side permission check. Only the shell needs one today."""
    def authorize(name: str):
        if name != SERVICE_SHELL:
            return None
        if not cfg.allow_shell:
            return "remote shell is disabled on this host"
        if trust.find_by_fingerprint(peer_fingerprint) is None:
            return "peer is not trusted for shell access"
        return None
    return authorize