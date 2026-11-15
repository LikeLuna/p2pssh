"""B.2 - Simultaneous-dial tie-break (Member 2).

Problem: A runs "chat B" and B runs "chat A" at the same moment.  Two connections
now exist between the same two peers for the same purpose:
    c1  initiated by A          c2  initiated by B
Each side only sees both of them AFTER the handshake (that is when it learns the
peer's fingerprint), so the decision must use only information both sides share.

Rule (the same answer on both machines, no messages needed):
    Keep the connection that was INITIATED by the peer whose fingerprint string
    is smaller.  Close the other one.

Scope of the rule:
  * Only OPPOSITE directions for the SAME peer and the SAME service are duplicates.
  * Two connections in the SAME direction are never duplicates (two file sends to
    the same peer are legitimate).
  * Different services never conflict (A sends a file while B opens a shell on A).

Use:  registry = DialRegistry(); keep = await registry.register(...)
      ... run the service ... ; registry.unregister(handle) in a finally block.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional

INITIATOR = "initiator"
RESPONDER = "responder"


def initiator_fingerprint(my_fp: str, peer_fp: str, role: str) -> str:
    """Fingerprint of whoever dialed this connection."""
    if role == INITIATOR:
        return my_fp
    if role == RESPONDER:
        return peer_fp
    raise ValueError(f"unknown role: {role!r}")


def wins(my_fp: str, peer_fp: str, role: str) -> bool:
    """True if a connection with this role is the one to keep.

    Both sides call this with their own point of view and get consistent answers:
    the connection initiated by the smaller fingerprint wins."""
    if my_fp == peer_fp:
        raise ValueError("a node cannot tie-break against itself")
    smaller = min(my_fp, peer_fp)
    return initiator_fingerprint(my_fp, peer_fp, role) == smaller


@dataclass(eq=False)
class Handle:
    peer_fp: str
    service: str
    role: str
    close: Callable[[], Awaitable[None]]
    superseded: bool = False
    _key: tuple = field(default=(), repr=False)


class DialRegistry:
    """Remembers live connections of this process, per (peer, service)."""

    def __init__(self, my_fp: str):
        self.my_fp = my_fp
        self._live: Dict[tuple, List[Handle]] = {}

    async def register(self, peer_fp: str, service: str, role: str,
                       close: Callable[[], Awaitable[None]]) -> Optional[Handle]:
        """Announce a connection that finished its handshake and service request.

        Returns a Handle if this connection is kept, or None if it lost the
        tie-break (it is then closed here: the caller just stops).  When it wins,
        any live OPPOSITE-direction duplicate is closed and marked superseded."""
        keep_me = wins(self.my_fp, peer_fp, role)
        key = (peer_fp, service)
        others = [h for h in self._live.get(key, []) if h.role != role and not h.superseded]
        if others and not keep_me:
            await close()                                   # lost: the duplicate stays
            return None
        handle = Handle(peer_fp, service, role, close, _key=key)
        self._live.setdefault(key, []).append(handle)
        for other in others:                                # won: the duplicate goes
            other.superseded = True
            try:
                await other.close()
            except Exception:
                pass
        return handle

    def unregister(self, handle: Optional[Handle]) -> None:
        if handle is None:
            return
        lst = self._live.get(handle._key)
        if lst and handle in lst:
            lst.remove(handle)
            if not lst:
                del self._live[handle._key]

    def live_count(self) -> int:
        return sum(len(v) for v in self._live.values())