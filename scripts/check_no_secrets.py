#!/usr/bin/env python3
"""Quét thư mục evidence sau khi chạy test.

- Mọi file: không được chứa giá trị bí mật trong .env (mật khẩu Redis, mật khẩu user, TOTP secret).
- File *.log (audit log, stdout của app): không được chứa full PAN test hay trường cvv.
Chỉ in tên loại dữ liệu và số lần gặp, không in giá trị.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG_PATTERNS = {
    "full PAN test": ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111"],
    'trường "cvv"': ['"cvv"'],
}


def load_secrets(env_path: Path) -> dict[str, str]:
    values = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and value and (key == "REDIS_PASSWORD" or key.startswith(("SEED_PASSWORD_", "SEED_TOTP_"))):
            values[key] = value
    return values


def main(directories: list[str]) -> int:
    """Trả về 1 nếu thấy bất kỳ giá trị nào."""
    env_secrets = load_secrets(ROOT / ".env")
    files = sorted(p for d in directories for p in Path(d).rglob("*") if p.is_file())
    hits = 0
    for path in files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for key, value in env_secrets.items():
            if value in text:
                print(f"{path}: chứa giá trị của {key}")
                hits += 1
        if path.suffix == ".log":
            for label, patterns in LOG_PATTERNS.items():
                count = sum(text.count(p) for p in patterns)
                if count:
                    print(f"{path}: {label} xuất hiện {count} lần")
                    hits += count
    print(f"Đã quét {len(files)} file với {len(env_secrets)} giá trị bí mật từ .env: "
          + ("không có rò rỉ" if hits == 0 else f"{hits} lần xuất hiện"))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["evidence"]))
