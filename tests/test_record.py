
import pytest

from record import RecordLayer, RecordError


KEY = b"K" * 32
PREFIX = b"TEST"


def make_pair():
    sender = RecordLayer(KEY, PREFIX)
    receiver = RecordLayer(KEY, PREFIX)
    return sender, receiver


def test_encrypt_and_decrypt():
    sender, receiver = make_pair()

    record = sender.seal(b"Hello Khushi")

    assert b"Hello Khushi" not in record
    assert receiver.open(record) == b"Hello Khushi"


def test_modified_record_is_rejected():
    sender, receiver = make_pair()

    record = bytearray(sender.seal(b"Important message"))
    record[8] ^= 1  # Change one ciphertext byte.

    with pytest.raises(RecordError):
        receiver.open(bytes(record))


def test_replayed_record_is_rejected():
    sender, receiver = make_pair()

    record = sender.seal(b"One-time message")

    assert receiver.open(record) == b"One-time message"

    with pytest.raises(RecordError):
        receiver.open(record)


def test_out_of_order_record_is_rejected():
    sender, receiver = make_pair()

    first = sender.seal(b"First")
    second = sender.seal(b"Second")

    with pytest.raises(RecordError):
        receiver.open(second)

    # Rejecting the wrong record must not advance the counter.
    assert receiver.open(first) == b"First"
    assert receiver.open(second) == b"Second"
