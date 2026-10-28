"""Unit test TOTP: vector RFC 6238 Appendix B (SHA-1, 8 chữ số) và cửa sổ ±1 step."""

import base64

import pytest

from lab01 import totp

RFC_KEY = b"12345678901234567890"
RFC_SHA1_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]
SECRET = base64.b32encode(RFC_KEY).decode()
NOW = 1_000_000_015.0  # giữa một time-step


@pytest.mark.parametrize("unix_time, expected", RFC_SHA1_VECTORS)
def test_rfc6238_sha1_vectors(unix_time: int, expected: str) -> None:
    assert totp.hotp(RFC_KEY, totp.time_step(unix_time), digits=8) == expected


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_accepts_clock_drift_of_one_step(offset: int) -> None:
    step = totp.time_step(NOW)
    code = totp.hotp(RFC_KEY, step + offset)
    assert totp.verify(SECRET, code, NOW) == step + offset


@pytest.mark.parametrize("offset", [-3, -2, 2, 3])
def test_rejects_codes_outside_window(offset: int) -> None:
    step = totp.time_step(NOW)
    code = totp.hotp(RFC_KEY, step + offset)
    assert totp.verify(SECRET, code, NOW) is None


@pytest.mark.parametrize("code", ["", "12345", "1234567", "12345a", "１２３４５６"])
def test_rejects_malformed_codes(code: str) -> None:
    assert totp.verify(SECRET, code, NOW) is None
