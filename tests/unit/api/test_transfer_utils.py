import pytest

from dragonslayer.api.transfer import encode_binary, decode_binary, BinaryTransfer


def test_encode_decode_roundtrip_small():
    data = b"abc123"
    enc = encode_binary(data, compress=True)
    dec = decode_binary(enc)
    assert dec == data


def test_encode_decode_roundtrip_large_with_gzip_prefix():
    data = b"X" * 4096
    enc = encode_binary(data, compress=True)
    assert enc.startswith("gzip:")
    dec = decode_binary(enc)
    assert dec == data


def test_stream_encode_decode():
    bt = BinaryTransfer(chunk_size=8, enable_compression=False)
    chunks = list(bt.stream_encode(binary_stream=type("B", (), {"read": lambda self, n: b""})()))
    # Nothing to encode from empty stream
    assert chunks == []


def test_checksum_and_verify():
    bt = BinaryTransfer()
    data = b"hello"
    meta = bt.create_transfer_metadata(data)
    assert bt.verify_checksum(data, meta["sha256"], "sha256")
