"""SQLite: bảng users và refunds; seed user demo từ biến môi trường."""

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone

from . import passwords
from .config import required_env

ROLES = frozenset({"CSKH", "KE_TOAN", "ADMIN"})

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    role          TEXT NOT NULL CHECK (role IN ('CSKH', 'KE_TOAN', 'ADMIN')),
    password_hash TEXT NOT NULL,
    totp_secret   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS refunds (
    id          INTEGER PRIMARY KEY,
    order_id    TEXT NOT NULL,
    amount      INTEGER NOT NULL CHECK (amount > 0),
    reason      TEXT NOT NULL,
    pan_last4   TEXT CHECK (pan_last4 IS NULL OR length(pan_last4) = 4),
    status      TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED')),
    created_by  INTEGER NOT NULL REFERENCES users(id),
    approved_by INTEGER REFERENCES users(id),
    created_at  TEXT NOT NULL,
    approved_at TEXT,
    -- Separation of Duties ở tầng dữ liệu: người duyệt không được là người tạo.
    CHECK (approved_by IS NULL OR approved_by <> created_by)
);
"""


def utcnow() -> str:
    """Thời điểm hiện tại, UTC, ISO 8601."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str) -> sqlite3.Connection:
    """Mở kết nối SQLite trả về Row truy cập theo tên cột."""
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def transaction(path: str) -> Iterator[sqlite3.Connection]:
    """Một kết nối cho một thao tác: commit khi xong, rollback khi lỗi."""
    conn = connect(path)
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _seed_users() -> list[tuple[str, str]]:
    users = []
    for item in filter(None, (part.strip() for part in os.environ.get("SEED_USERS", "").split(","))):
        username, _, role = item.partition(":")
        if role not in ROLES:
            raise RuntimeError(f"SEED_USERS: role '{role}' của '{username}' không thuộc {sorted(ROLES)}")
        users.append((username, role))
    if not users:
        raise RuntimeError("SEED_USERS trống (xem .env.example)")
    return users


def init_db(path: str) -> None:
    """Tạo schema; DB còn trống thì seed user demo (mật khẩu và TOTP secret lấy từ .env)."""
    with transaction(path) as conn:
        conn.executescript(SCHEMA)
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return
        for username, role in _seed_users():
            key = username.upper()
            conn.execute(
                "INSERT INTO users (username, role, password_hash, totp_secret) VALUES (?, ?, ?, ?)",
                (
                    username,
                    role,
                    passwords.hash_password(required_env(f"SEED_PASSWORD_{key}")),
                    required_env(f"SEED_TOTP_{key}"),
                ),
            )
