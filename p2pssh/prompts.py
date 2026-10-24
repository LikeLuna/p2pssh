"""Trust prompts shown to the user (owner: Member 1).

The handshake (A.2) calls decide_initiator() / decide_responder() after it has
verified the peer's signature. These functions are the ONLY place where trust
questions are shown, so identity.py and handshake.py never print or read input.

All text shown to the user is cleaned first: a malicious peer must not be able to
inject terminal escape sequences through its name.
"""
import sys
import unicodedata
from enum import Enum

from .identity import TrustError, TrustResult, fingerprint

MAX_SHOWN_NAME = 64
MAX_ATTEMPTS = 3


class TrustDecision(Enum):
    ACCEPTED_KNOWN = "accepted_known"          # already trusted, nothing shown
    ACCEPTED_NEW = "accepted_new"              # user said yes, peer is now stored
    REJECTED_NEW = "rejected_new"              # user said no (or gave no answer)
    REJECTED_CHANGED = "rejected_changed"      # key differs from the stored one

    @property
    def accepted(self) -> bool:
        return self in (TrustDecision.ACCEPTED_KNOWN, TrustDecision.ACCEPTED_NEW)


def clean_text(text, limit: int = MAX_SHOWN_NAME) -> str:
    """Make untrusted text safe to print: no control characters, bounded length."""
    text = str(text)
    safe = "".join(
        ch if (ch.isprintable() and unicodedata.category(ch)[0] != "C") else "?"
        for ch in text
    )
    return safe if len(safe) <= limit else safe[: limit - 3] + "..."


def _red(text: str) -> str:
    return f"\033[1;31m{text}\033[0m" if sys.stderr.isatty() else text


def _default_out(text: str) -> None:
    print(text, file=sys.stderr)


def changed_warning_text(name, old_fp: str, new_fp: str) -> str:
    return "\n".join([
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
        "@  WARNING: THE KEY FOR THIS PEER HAS CHANGED!                  @",
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
        f"Peer:            {clean_text(name)}",
        f"Trusted key:     {clean_text(old_fp, 80)}",
        f"Key presented:   {clean_text(new_fp, 80)}",
        "Someone may be impersonating this peer, or they reinstalled.",
        "Connection REFUSED. If you are sure the change is legitimate, verify the",
        "new fingerprint with the peer by another channel, then run:",
        f"    p2pssh trust remove {clean_text(name)}",
    ])


def new_peer_text(name, fp: str) -> str:
    return "\n".join([
        f"New peer \"{clean_text(name)}\".",
        f"Fingerprint: {clean_text(fp, 80)}",
        "Compare this fingerprint with the peer (call or message them).",
        "Only trust it if it matches exactly.",
    ])


def confirm_new_peer(name, pub: bytes, *, ask=input, out=_default_out) -> bool:
    """Show the fingerprint and ask yes/no. Anything except a clear yes is a no."""
    out(new_peer_text(name, fingerprint(pub)))
    for _ in range(MAX_ATTEMPTS):
        try:
            answer = ask("Trust this peer? (yes/no): ")
        except (EOFError, KeyboardInterrupt):
            out("No answer, peer not trusted.")
            return False
        answer = str(answer).strip().lower()
        if answer in ("yes", "y"):
            return True
        if answer in ("no", "n"):
            return False
        out("Please type yes or no.")
    out("No valid answer, peer not trusted.")
    return False


def decide_initiator(trust, peer_name: str, pub: bytes, *, ask=input, out=_default_out):
    """We dialed a peer we know by name. Called after the signature was verified."""
    result = trust.check(peer_name, pub)
    if result == TrustResult.TRUSTED:
        return TrustDecision.ACCEPTED_KNOWN
    if result == TrustResult.CHANGED:
        old_fp = trust.list_peers().get(peer_name, {}).get("fingerprint", "?")
        out(_red(changed_warning_text(peer_name, old_fp, fingerprint(pub))))
        return TrustDecision.REJECTED_CHANGED
    # NEW
    if not confirm_new_peer(peer_name, pub, ask=ask, out=out):
        return TrustDecision.REJECTED_NEW
    return _store_new(trust, peer_name, pub, out)


def decide_responder(trust, label: str, pub: bytes, *, ask=input, out=_default_out):
    """A peer dialed us. We have its key but no trusted name, so look it up by
    fingerprint. Unknown means NEW; the 'key changed' alarm cannot fire here."""
    known = trust.find_by_fingerprint(fingerprint(pub))
    if known is not None:
        return TrustDecision.ACCEPTED_KNOWN
    if not confirm_new_peer(label, pub, ask=ask, out=out):
        return TrustDecision.REJECTED_NEW
    return _store_new(trust, label, pub, out)


def _store_new(trust, name: str, pub: bytes, out):
    try:
        trust.add(name, pub)
    except TrustError:
        # The label is already taken by a different key: never overwrite it.
        out(_red(f"The name \"{clean_text(name)}\" is already trusted with a different key. "
                 f"Refusing. Remove the old entry first if that is intended."))
        return TrustDecision.REJECTED_CHANGED
    except ValueError as exc:
        out(f"Cannot store this peer: {exc}")
        return TrustDecision.REJECTED_NEW
    return TrustDecision.ACCEPTED_NEW