import pytest

from p2pssh.identity import TrustStore, fingerprint
from p2pssh.prompts import (
    TrustDecision,
    changed_warning_text,
    clean_text,
    confirm_new_peer,
    decide_initiator,
    decide_responder,
)

KEY1 = bytes(range(32))
KEY2 = bytes(range(1, 33))


@pytest.fixture
def store(tmp_path):
    return TrustStore(tmp_path / "known_peers.json")


class Script:
    """Fake user: returns scripted answers and records what was shown."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.questions = 0
        self.shown = []

    def ask(self, prompt):
        self.questions += 1
        if not self.answers:
            raise EOFError
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def out(self, text):
        self.shown.append(text)

    @property
    def text(self):
        return "\n".join(self.shown)


def run(fn, store, name, pub, *answers):
    s = Script(*answers)
    return fn(store, name, pub, ask=s.ask, out=s.out), s


# ---------- clean_text ----------

def test_clean_text_removes_terminal_escapes():
    assert "\x1b" not in clean_text("ben\x1b[31mEVIL\x1b[0m")
    assert "\n" not in clean_text("a\nb")
    assert "\x07" not in clean_text("bell\x07")


def test_clean_text_truncates():
    assert len(clean_text("x" * 500)) <= 64


def test_clean_text_keeps_unicode_names():
    assert clean_text("बेन-🔑") == "बेन-🔑"


# ---------- confirm_new_peer ----------

@pytest.mark.parametrize("answer", ["yes", "y", "YES", "  Yes  "])
def test_confirm_accepts_yes(answer):
    s = Script(answer)
    assert confirm_new_peer("ben", KEY1, ask=s.ask, out=s.out) is True


@pytest.mark.parametrize("answer", ["no", "n", "NO"])
def test_confirm_rejects_no(answer):
    s = Script(answer)
    assert confirm_new_peer("ben", KEY1, ask=s.ask, out=s.out) is False


def test_confirm_shows_fingerprint():
    s = Script("no")
    confirm_new_peer("ben", KEY1, ask=s.ask, out=s.out)
    assert fingerprint(KEY1) in s.text


def test_confirm_reasks_on_garbage_then_accepts():
    s = Script("maybe", "", "yes")
    assert confirm_new_peer("ben", KEY1, ask=s.ask, out=s.out) is True
    assert s.questions == 3


def test_confirm_gives_up_after_three_garbage_answers():
    s = Script("a", "b", "c", "yes")
    assert confirm_new_peer("ben", KEY1, ask=s.ask, out=s.out) is False
    assert s.questions == 3


@pytest.mark.parametrize("exc", [EOFError(), KeyboardInterrupt()])
def test_confirm_no_input_means_no(exc):
    s = Script(exc)
    assert confirm_new_peer("ben", KEY1, ask=s.ask, out=s.out) is False


def test_confirm_malicious_name_cannot_inject_escapes():
    s = Script("no")
    confirm_new_peer("ben\x1b[2J\x1b[31m", KEY1, ask=s.ask, out=s.out)
    assert "\x1b" not in s.text


# ---------- decide_initiator ----------

def test_initiator_known_peer_is_silent(store):
    store.add("ben", KEY1)
    decision, s = run(decide_initiator, store, "ben", KEY1)
    assert decision == TrustDecision.ACCEPTED_KNOWN
    assert decision.accepted
    assert s.questions == 0 and s.shown == []


def test_initiator_new_peer_accepted_is_stored(store):
    decision, s = run(decide_initiator, store, "ben", KEY1, "yes")
    assert decision == TrustDecision.ACCEPTED_NEW
    assert store.find_by_fingerprint(fingerprint(KEY1)) == "ben"


def test_initiator_new_peer_rejected_is_not_stored(store):
    decision, _ = run(decide_initiator, store, "ben", KEY1, "no")
    assert decision == TrustDecision.REJECTED_NEW
    assert not decision.accepted
    assert store.find_by_fingerprint(fingerprint(KEY1)) is None


def test_initiator_changed_key_is_refused_without_asking(store):
    store.add("ben", KEY1)
    decision, s = run(decide_initiator, store, "ben", KEY2, "yes")
    assert decision == TrustDecision.REJECTED_CHANGED
    assert s.questions == 0                        # never offers to accept
    assert fingerprint(KEY1) in s.text and fingerprint(KEY2) in s.text
    assert "p2pssh trust remove ben" in s.text
    assert store.find_by_fingerprint(fingerprint(KEY1)) == "ben"   # old key untouched
    assert store.find_by_fingerprint(fingerprint(KEY2)) is None


def test_changed_warning_cleans_hostile_name():
    text = changed_warning_text("ben\x1b[2J", "SHA256:a", "SHA256:b")
    assert "\x1b" not in text


# ---------- decide_responder ----------

def test_responder_known_key_is_silent(store):
    store.add("ben", KEY1)
    decision, s = run(decide_responder, store, "1.2.3.4:5000", KEY1)
    assert decision == TrustDecision.ACCEPTED_KNOWN
    assert s.questions == 0


def test_responder_unknown_key_is_new_and_stored_under_label(store):
    decision, _ = run(decide_responder, store, "1.2.3.4:5000", KEY1, "yes")
    assert decision == TrustDecision.ACCEPTED_NEW
    assert store.find_by_fingerprint(fingerprint(KEY1)) == "1.2.3.4:5000"


def test_responder_unknown_key_rejected(store):
    decision, _ = run(decide_responder, store, "1.2.3.4:5000", KEY1, "no")
    assert decision == TrustDecision.REJECTED_NEW
    assert store.find_by_fingerprint(fingerprint(KEY1)) is None


def test_responder_label_already_used_by_other_key_never_overwrites(store):
    store.add("1.2.3.4:5000", KEY1)
    decision, s = run(decide_responder, store, "1.2.3.4:5000", KEY2, "yes")
    assert decision == TrustDecision.REJECTED_CHANGED
    assert store.find_by_fingerprint(fingerprint(KEY1)) == "1.2.3.4:5000"
    assert store.find_by_fingerprint(fingerprint(KEY2)) is None


def test_responder_empty_label_is_rejected_cleanly(store):
    decision, _ = run(decide_responder, store, "", KEY1, "yes")
    assert decision == TrustDecision.REJECTED_NEW