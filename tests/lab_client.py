"""Client test: gửi request thật vào app, tự quản lý cookie, ghi evidence Markdown kèm audit log."""

import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import redis

from lab01 import totp

BASE_URL = os.environ.get("BASE_URL", "http://app:8000")
AUDIT_LOG = Path(os.environ.get("AUDIT_LOG", "/logs/audit.log"))
EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "/evidence"))
COOKIE_NAME = "__Host-sid"
USER_AGENT = "attmdt-lab01-tests/1.0"
STEP = 30

_COOKIE_RE = re.compile(rf"{re.escape(COOKIE_NAME)}=([^;]*)")
_HIDDEN_BODY_KEYS = {"password", "current_password", "new_password"}

# Trạng thái dùng chung giữa các test (chạy tuần tự T1 -> T9).
PASSWORDS: dict[str, str] = {}
TOTP_SECRETS: dict[str, str] = {}
SEEN_SIDS: set[str] = set()
LAST_STEP: dict[str, int] = {}
RESULTS: dict[str, tuple[str, str, str]] = {}


def seed_users() -> list[str]:
    return [item.split(":")[0] for item in os.environ["SEED_USERS"].split(",") if item]


def credentials(user: str) -> tuple[str, str]:
    """Mật khẩu và TOTP secret hiện tại của user (giá trị seed hoặc giá trị đã đổi trong test)."""
    password = PASSWORDS.setdefault(user, os.environ[f"SEED_PASSWORD_{user.upper()}"])
    secret = TOTP_SECRETS.setdefault(user, os.environ[f"SEED_TOTP_{user.upper()}"])
    return password, secret


def redis_client() -> redis.Redis:
    return redis.Redis(
        host=os.environ.get("REDIS_HOST", "redis"),
        password=os.environ["REDIS_PASSWORD"],
        decode_responses=True,
    )


def sid_hash16(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()[:16]


def session_key(sid: str) -> str:
    return f"sess:{hashlib.sha256(sid.encode()).hexdigest()}"


def show_sid(sid: str | None) -> str:
    """Evidence không chứa Session ID đầy đủ: chỉ đầu/cuối và hash (khớp session_id_hash trong audit)."""
    if not sid:
        return "(không có)"
    return f"{sid[:6]}...{sid[-4:]} (sha256:{sid_hash16(sid)})"


def cookie_sid(response: httpx.Response) -> str | None:
    """Session ID trong Set-Cookie của response; None nếu không có hoặc là lệnh xóa cookie."""
    for header in response.headers.get_list("set-cookie"):
        match = _COOKIE_RE.match(header)
        if match:
            return match.group(1).strip('"') or None
    return None


def set_cookie_headers(response: httpx.Response) -> list[str]:
    return [h for h in response.headers.get_list("set-cookie") if h.startswith(COOKIE_NAME)]


def audit_events(correlation_id: str) -> list[dict[str, Any]]:
    if not AUDIT_LOG.exists():
        return []
    events = []
    for line in AUDIT_LOG.read_text(encoding="utf-8").splitlines():
        if correlation_id in line:
            event = json.loads(line)
            if event.get("correlation_id") == correlation_id:
                events.append(event)
    return events


def _hide_body(body: Any) -> Any:
    if isinstance(body, dict):
        return {k: "***(ẩn)" if k in _HIDDEN_BODY_KEYS else v for k, v in body.items()}
    return body


def _hide_response(payload: Any) -> Any:
    if isinstance(payload, dict) and "otpauth_uri" in payload:
        payload = dict(payload)
        payload["otpauth_uri"] = re.sub(r"secret=[A-Z2-7]+", "secret=***(ẩn)", payload["otpauth_uri"])
    return payload


class Evidence:
    """Một file evidence Markdown cho một test."""

    def __init__(self, test_id: str, slug: str, title: str, pass_when: str) -> None:
        self.test_id = test_id
        self.title = title
        self.filename = f"{test_id}-{slug}.md"
        self.counter = 0
        self.lines = [f"# {test_id} - {title}", "", f"**PASS khi:** {pass_when}", "", "", ""]

    def section(self, title: str) -> None:
        self.lines += ["", f"## {title}", ""]

    def text(self, line: str) -> None:
        self.lines += [line, ""]

    def block(self, content: str, lang: str = "") -> None:
        self.lines += [f"```{lang}", content.rstrip(), "```", ""]

    def write(self, outcome: str, failure: str | None = None) -> None:
        self.lines[4] = f"**Kết quả:** {outcome}"
        if failure:
            self.section("Lỗi")
            self.block(failure[-3000:])
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        (EVIDENCE_DIR / self.filename).write_text("\n".join(self.lines) + "\n", encoding="utf-8")
        RESULTS[self.test_id] = (self.title, outcome, self.filename)


class Api:
    """Gửi request, ghi request/response/audit vào evidence."""

    def __init__(self, ev: Evidence) -> None:
        self.ev = ev
        self.http = httpx.Client(base_url=BASE_URL, timeout=10)
        self.last_audit: list[dict[str, Any]] = []

    def call(
        self,
        method: str,
        path: str,
        *,
        label: str,
        sid: str | None = None,
        body: Any = None,
        user_agent: str = USER_AGENT,
    ) -> httpx.Response:
        self.ev.counter += 1
        correlation_id = f"{self.ev.test_id}-{self.ev.counter:02d}-{uuid.uuid4().hex[:8]}"
        headers = {"User-Agent": user_agent, "X-Correlation-ID": correlation_id}
        if sid:
            headers["Cookie"] = f"{COOKIE_NAME}={sid}"
        response = self.http.request(method, path, json=body, headers=headers)
        self.http.cookies.clear()  # cookie chỉ đi qua header Cookie do test chỉ định
        for value in (sid, cookie_sid(response)):
            if value:
                SEEN_SIDS.add(value)
        self.last_audit = audit_events(correlation_id)
        self._record(label, method, path, sid, user_agent, correlation_id, body, response)
        return response

    def _record(
        self,
        label: str,
        method: str,
        path: str,
        sid: str | None,
        user_agent: str,
        correlation_id: str,
        body: Any,
        response: httpx.Response,
    ) -> None:
        request_lines = [
            f"{method} {path}",
            f"X-Correlation-ID: {correlation_id}",
            f"User-Agent: {user_agent}",
        ]
        if sid:
            request_lines.append(f"Cookie: {COOKIE_NAME}={show_sid(sid)}")
        if body is not None:
            request_lines += ["", json.dumps(_hide_body(body), ensure_ascii=False, indent=2)]
        response_lines = [f"HTTP {response.status_code}"]
        for header in set_cookie_headers(response):
            value = cookie_sid(response)
            response_lines.append(
                "Set-Cookie: " + (header.replace(value, show_sid(value)) if value else header)
            )
        try:
            payload = response.json()
        except ValueError:
            payload = response.text
        response_lines += ["", json.dumps(_hide_response(payload), ensure_ascii=False, indent=2)]

        self.ev.lines += [f"### {label}", "", "Request:"]
        self.ev.block("\n".join(request_lines), "http")
        self.ev.lines.append("Response:")
        self.ev.block("\n".join(response_lines), "http")
        if self.last_audit:
            self.ev.lines.append("Audit log (cùng X-Correlation-ID):")
            self.ev.block("\n".join(json.dumps(e, ensure_ascii=False) for e in self.last_audit), "json")

    def actions(self) -> list[tuple[str, str]]:
        return [(e["action"], e["result"]) for e in self.last_audit]


def fresh_code(user: str) -> tuple[int, str]:
    """Mã TOTP của một time-step user chưa dùng; nếu đã dùng thì chờ sang step sau (server chặn replay)."""
    _, secret = credentials(user)
    while True:
        now = time.time()
        step = totp.time_step(now, STEP)
        if step > LAST_STEP.get(user, -1):
            LAST_STEP[user] = step
            return step, totp.totp(secret, now)
        time.sleep((step + 1) * STEP - now + 0.2)


def password_step(api: Api, user: str, *, sid: str | None = None, user_agent: str = USER_AGENT) -> str:
    """Bước 1 (password); trả về Session ID chờ MFA."""
    password, _ = credentials(user)
    response = api.call(
        "POST",
        "/auth/login",
        label=f"{user}: bước 1 - password",
        sid=sid,
        body={"username": user, "password": password},
        user_agent=user_agent,
    )
    assert response.status_code == 200, response.text
    pending = cookie_sid(response)
    assert pending
    return pending


def login(api: Api, user: str, *, sid: str | None = None, user_agent: str = USER_AGENT) -> str:
    """Đăng nhập đủ 2 bước; trả về Session ID sau MFA."""
    pending = password_step(api, user, sid=sid, user_agent=user_agent)
    _, code = fresh_code(user)
    response = api.call(
        "POST",
        "/auth/mfa",
        label=f"{user}: bước 2 - TOTP",
        sid=pending,
        body={"code": code},
        user_agent=user_agent,
    )
    assert response.status_code == 200, response.text
    sid_after = cookie_sid(response)
    assert sid_after
    return sid_after
