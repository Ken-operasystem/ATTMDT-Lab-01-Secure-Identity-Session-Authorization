"""Băm mật khẩu bằng scrypt (hashlib), lưu dạng scrypt$n$r$p$salt$hash."""

import base64
import hashlib
import hmac
import os

_N, _R, _P, _DKLEN = 2 ** 14, 8, 1, 32


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def hash_password(password: str) -> str:
    """Băm mật khẩu với salt ngẫu nhiên 16 byte."""
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """So sánh hằng thời gian giữa mật khẩu nhập và hash đã lưu."""
    try:
        algo, n, r, p, salt_b64, hash_b64 = stored.split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    expected = base64.b64decode(hash_b64)
    digest = hashlib.scrypt(
        password.encode(),
        salt=base64.b64decode(salt_b64),
        n=int(n),
        r=int(r),
        p=int(p),
        dklen=len(expected),
    )
    return hmac.compare_digest(digest, expected)


# Dùng khi username không tồn tại, để thời gian phản hồi không lộ user nào có thật.
DUMMY_HASH = hash_password(os.urandom(16).hex())
