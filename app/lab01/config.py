"""Cấu hình ứng dụng, đọc từ biến môi trường."""

import os
from dataclasses import dataclass


def required_env(name: str, default: str | None = None) -> str:
    """Đọc biến môi trường bắt buộc; thiếu thì báo đúng tên biến."""
    value = os.environ.get(name, default)
    if not value:
        raise RuntimeError(f"Thiếu biến môi trường {name} (xem .env.example)")
    return value


@dataclass(frozen=True)
class Settings:
    """Tham số bảo mật của lab; giá trị mặc định theo đề Lab 01."""

    redis_host: str
    redis_port: int
    redis_password: str
    db_path: str
    audit_log_path: str
    totp_step: int = 30
    totp_digits: int = 6
    totp_window: int = 1
    idle_timeout: int = 15 * 60
    absolute_timeout: int = 8 * 60 * 60
    pending_mfa_timeout: int = 5 * 60
    mfa_max_failures: int = 5
    mfa_failure_window: int = 5 * 60
    cookie_name: str = "__Host-sid"

    @property
    def replay_ttl(self) -> int:
        """TTL của key chống replay.

        Mã của step s còn được nhận khi step hiện tại nằm trong [s - window, s + window],
        nên kể từ lúc key được ghi, mã còn sống tối đa (2 * window + 1) * step giây
        (90 giây với window = 1). Cộng thêm 1 step dự phòng lệch giờ: 120 giây.
        """
        return (2 * self.totp_window + 2) * self.totp_step


def load_settings() -> Settings:
    """Tạo Settings từ môi trường container."""
    return Settings(
        redis_host=required_env("REDIS_HOST", "redis"),
        redis_port=int(required_env("REDIS_PORT", "6379")),
        redis_password=required_env("REDIS_PASSWORD"),
        db_path=required_env("DB_PATH", "/data/lab01.db"),
        audit_log_path=required_env("AUDIT_LOG_PATH", "/app/logs/audit.log"),
    )
