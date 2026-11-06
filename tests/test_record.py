
import pytest

from p2pssh.record import RecordLayer, RecordError


SEND_KEY = b"K" * 32
RECV_KEY = b"R" * 32


def make_pair():
    # Sender sends using SEND_KEY.
    # Receiver receives using the same key.
    sender = RecordLayer(
        send_key=SEND_KEY,
        recv_key=RECV_KEY
    )

    receiver = RecordLayer(
        send_key=RECV_KEY,
        recv_key=SEND_KEY
    )

    return sender, receiver


def test_encrypt_and_decrypt():
    sender, receiver = make_pair()

    record = sender.seal(b"Hello Khushi")

    assert b"Hello Khushi" not in record
    assert receiver.open(record) == b"Hello Khushi"


def test_modified_record_is_rejected():
    sender, receiver = make_pair()

    record = bytearray(sender.seal(b"Important message"))

    # Change one ciphertext byte.
    record[8] ^= 1

    with pytest.raises(RecordError):
        receiver.open(bytes(record))


def test_replayed_record_is_rejected():
    sender, receiver = make_pair()

    record = sender.seal(b"One-time message")

    assert receiver.open(record) == b"One-time message"

    # Same record cannot be decrypted twice.
    with pytest.raises(RecordError):
        receiver.open(record)


def test_out_of_order_record_is_rejected():
    sender, receiver = make_pair()

    first = sender.seal(b"First")
    second = sender.seal(b"Second")

    # Second record cannot arrive before first.
    with pytest.raises(RecordError):
        receiver.open(second)

    # Rejecting the wrong record must not advance the counter.
    assert receiver.open(first) == b"First"
    assert receiver.open(second) == b"Second"


def test_send_and_receive_keys_are_independent():
    sender, receiver = make_pair()

    # Sender's send key is different from its receive key.
    assert sender.send_aes != sender.recv_aes

    record = sender.seal(b"Directional encryption")

    assert receiver.open(record) == b"Directional encryption"
