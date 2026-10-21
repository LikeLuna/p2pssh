"""B.1 - LAN peer discovery over mDNS (Member 1).

Interface (frozen in README section 7):
    Discovery.announce(name, port, fingerprint)
    Discovery.browse(callback)
    Discovery.peers() -> list[PeerInfo]

Discovery only *finds* peers. The fingerprint it reports is a hint for the UI;
trust is decided later by the handshake + TrustStore, never by mDNS.
"""
import re
import socket
import threading
from dataclasses import dataclass

from zeroconf import ServiceBrowser, ServiceInfo, ServiceStateChange, Zeroconf

SERVICE_TYPE = "_p2pssh._tcp.local."
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/=_-]{10,64}$")


class DiscoveryError(Exception):
    pass


@dataclass(frozen=True)
class PeerInfo:
    name: str
    host: str
    port: int
    fingerprint: str


def _validate(name, port, fingerprint):
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise DiscoveryError("name must be 1-32 chars of letters, digits, . _ -")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise DiscoveryError("port must be 1-65535")
    if not isinstance(fingerprint, str) or not _FP_RE.match(fingerprint):
        raise DiscoveryError("fingerprint must look like 'SHA256:...'")


def _local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def peer_from_info(info) -> "PeerInfo | None":
    """Turn a zeroconf ServiceInfo into a PeerInfo. Returns None if malformed."""
    try:
        props = {k.decode(): (v or b"").decode() for k, v in info.properties.items()}
        name = info.name[: -len("." + SERVICE_TYPE)]
        addrs = info.parsed_addresses()
        fp = props.get("fp", "")
        if not addrs or not _NAME_RE.match(name) or not _FP_RE.match(fp):
            return None
        if not (1 <= info.port <= 65535):
            return None
        return PeerInfo(name, addrs[0], info.port, fp)
    except Exception:  # malformed packets from the network must never crash us
        return None


class Discovery:
    def __init__(self, zeroconf: Zeroconf = None):
        self._zc = zeroconf or Zeroconf()
        self._own_zc = zeroconf is None
        self._lock = threading.Lock()
        self._peers: dict[str, PeerInfo] = {}
        self._info = None
        self._own_name = None
        self._browser = None
        self._callback = None

    # ---- announce -------------------------------------------------------
    def announce(self, name: str, port: int, fingerprint: str) -> None:
        _validate(name, port, fingerprint)
        if self._info is not None:
            raise DiscoveryError("already announcing; call close() first")
        ip = _local_ip()
        self._info = ServiceInfo(
            SERVICE_TYPE,
            f"{name}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(ip)],
            port=port,
            properties={"fp": fingerprint, "v": "1"},
        )
        self._own_name = name
        self._zc.register_service(self._info)

    # ---- browse ---------------------------------------------------------
    def browse(self, callback=None) -> None:
        """Start listening. callback(event, PeerInfo) with event 'added'/'removed'."""
        if self._browser is not None:
            return
        self._callback = callback
        self._browser = ServiceBrowser(
            self._zc, SERVICE_TYPE, handlers=[self._on_change]
        )

    def _on_change(self, zeroconf, service_type, name, state_change):
        short = name[: -len("." + service_type)]
        if short == self._own_name:
            return  # ignore ourselves
        if state_change in (ServiceStateChange.Added, ServiceStateChange.Updated):
            info = zeroconf.get_service_info(service_type, name, timeout=2000)
            peer = peer_from_info(info) if info else None
            if peer:
                self._add(peer)
        elif state_change is ServiceStateChange.Removed:
            self._remove(short)

    def _add(self, peer: PeerInfo) -> None:
        with self._lock:
            self._peers[peer.name] = peer
        if self._callback:
            self._callback("added", peer)

    def _remove(self, name: str) -> None:
        with self._lock:
            peer = self._peers.pop(name, None)
        if peer and self._callback:
            self._callback("removed", peer)

    # ---- query / shutdown -----------------------------------------------
    def peers(self) -> list:
        with self._lock:
            return list(self._peers.values())

    def close(self) -> None:
        if self._info is not None:
            self._zc.unregister_service(self._info)
            self._info = None
        if self._browser is not None:
            self._browser.cancel()
            self._browser = None
        if self._own_zc:
            self._zc.close()
def parse_hostport(text: str):
    """'192.168.1.5:5000' -> ('192.168.1.5', 5000). Manual peer entry."""
    host, sep, port = str(text).rpartition(":")
    if not sep or not host or not port.isdigit() or not (1 <= int(port) <= 65535):
        raise DiscoveryError("address must look like IP:port, e.g. 192.168.1.5:5000")
    return host, int(port)