"""Audit log dạng JSON lines; mọi bản ghi đi qua bộ lọc che dữ liệu nhạy cảm trước khi ghi."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

# Giá trị của các key này không bao giờ được ghi ra log.
REDACT_KEYS = frozenset({
    "password", "current_password", "new_password",
    "code", "otp", "totp", "secret", "totp_secret", "otpauth_uri",
    "token", "sid", "session_id", "cookie", "authorization",
    "cvv", "cvc",
})

# Dãy 13-19 chữ số (cho phép dấu cách hoặc gạch giữa các số): coi là số thẻ.
_PAN_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")

# Trường do server tự sinh, không chứa input của client.
_TRUSTED_FIELDS = frozenset({"timestamp", "session_id_hash"})


def mask_pan(text: str) -> str:
    """Che số thẻ, chỉ giữ 4 số cuối: 4111 1111 1111 1111 -> ************1111."""

    def _mask(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group())
        return "*" * (len(digits) - 4) + digits[-4:]

    return _PAN_RE.sub(_mask, text)


def scrub(value: Any, key: str | None = None) -> Any:
    """Xóa giá trị của key nhạy cảm và che số thẻ trong mọi chuỗi, đệ quy."""
    if key is not None and key.lower() in REDACT_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: scrub(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(v) for v in value]
    if isinstance(value, str):
        return mask_pan(value)
    return value


class AuditLogger:
    """Ghi audit event ra file (cho điều tra) và stdout (cho log tập trung/SIEM)."""

    def __init__(self, path: str) -> None:
        self._logger = logging.getLogger("lab01.audit")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        if not self._logger.handlers:
            formatter = logging.Formatter("%(message)s")
            for handler in (logging.FileHandler(path, encoding="utf-8"), logging.StreamHandler()):
                handler.setFormatter(formatter)
                self._logger.addHandler(handler)

    def write(
        self,
        *,
        action: str,
        result: str,
        actor_id: int | None,
        role: str | None,
        object_id: str | None,
        source_ip: str,
        correlation_id: str,
        session_id_hash: str | None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Ghi một event với bộ trường tối thiểu theo đề, sau khi đã che dữ liệu."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "action": action,
            "result": result,
            "actor_id": actor_id,
            "role": role,
            "object_id": object_id,
            "source_ip": source_ip,
            "correlation_id": correlation_id,
            "session_id_hash": session_id_hash,
            "details": details or {},
        }
        safe = {k: v if k in _TRUSTED_FIELDS else scrub(v, k) for k, v in record.items()}
        self._logger.info(json.dumps(safe, ensure_ascii=False))
