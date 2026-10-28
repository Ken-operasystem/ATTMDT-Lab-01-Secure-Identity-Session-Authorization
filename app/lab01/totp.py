"""TOTP theo RFC 6238: HOTP (RFC 4226) với bộ đếm là time-step."""

import base64
import hashlib
import hmac
import os
import re
import struct
import sys
import time
from urllib.parse import quote

_DIGITS_RE = re.compile(r"[0-9]+")


def decode_secret(secret_b32: str) -> bytes:
    """Giải mã secret Base32 (chấp nhận thiếu padding, chữ thường, khoảng trắng)."""
    cleaned = secret_b32.replace(" ", "").upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def new_secret() -> str:
    """Secret 160 bit ngẫu nhiên, mã hóa Base32 như các app Authenticator dùng."""
    return base64.b32encode(os.urandom(20)).decode()


def hotp(key: bytes, counter: int, digits: int = 6) -> str:
    """HOTP RFC 4226: HMAC-SHA1(key, counter) rồi dynamic truncation."""
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % 10 ** digits).zfill(digits)


def time_step(now: float, step: int = 30) -> int:
    """T = floor((now - T0) / X), với T0 = 0 (Unix epoch) và X = step."""
    return int(now // step)


def totp(secret_b32: str, now: float, step: int = 30, digits: int = 6) -> str:
    """Mã TOTP tại thời điểm now."""
    return hotp(decode_secret(secret_b32), time_step(now, step), digits)


def verify(
    secret_b32: str, code: str, now: float, step: int = 30, digits: int = 6, window: int = 1
) -> int | None:
    """Trả về time-step khớp với mã, hoặc None nếu mã sai định dạng, sai, hoặc ngoài cửa sổ ±window."""
    if len(code) != digits or not _DIGITS_RE.fullmatch(code):
        return None
    key = decode_secret(secret_b32)
    current = time_step(now, step)
    matched = None
    for candidate in range(current - window, current + window + 1):
        if hmac.compare_digest(hotp(key, candidate, digits), code):
            matched = candidate
    return matched


def provisioning_uri(secret_b32: str, account: str, issuer: str = "ATTMDT-Lab01") -> str:
    """URI otpauth:// để app Authenticator quét QR khi đăng ký lại MFA."""
    label = quote(f"{issuer}:{account}")
    return (
        f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}"
        "&algorithm=SHA1&digits=6&period=30"
    )


def _main(argv: list[str]) -> int:
    """In mã hiện tại của user demo; secret đọc từ biến SEED_TOTP_<USER>, không qua tham số."""
    if len(argv) != 2:
        print("usage: python -m lab01.totp <username>", file=sys.stderr)
        return 2
    variable = f"SEED_TOTP_{argv[1].upper()}"
    secret = os.environ.get(variable)
    if not secret:
        print(f"thiếu biến {variable}", file=sys.stderr)
        return 2
    print(totp(secret, time.time()))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
