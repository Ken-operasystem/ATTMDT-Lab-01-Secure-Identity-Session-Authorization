#!/usr/bin/env python3
"""Tạo file .env: mật khẩu Redis, mật khẩu và TOTP secret ngẫu nhiên cho từng user demo.

Không in giá trị nào ra màn hình. File .env đã nằm trong .gitignore.
"""

import base64
import os
import secrets
import sys
from pathlib import Path

USERS = {"cskh01": "CSKH", "cskh02": "CSKH", "ketoan01": "KE_TOAN", "admin01": "ADMIN"}


def main() -> int:
    """Ghi .env ở thư mục gốc repo nếu chưa có."""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        print(f"{env_path.name} đã có, giữ nguyên")
        return 0
    lines = [
        f"REDIS_PASSWORD={secrets.token_hex(24)}",
        "SEED_USERS=" + ",".join(f"{user}:{role}" for user, role in USERS.items()),
    ]
    for user in USERS:
        key = user.upper()
        lines.append(f"SEED_PASSWORD_{key}={secrets.token_urlsafe(18)}")
        lines.append(f"SEED_TOTP_{key}={base64.b32encode(os.urandom(20)).decode()}")
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"Đã tạo {env_path.name} cho {len(USERS)} user demo: {', '.join(USERS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
