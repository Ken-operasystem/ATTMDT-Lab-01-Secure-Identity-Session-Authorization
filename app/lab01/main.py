"""API cổng quản trị sàn TMĐT: đăng nhập 2 bước, session, RBAC + SoD cho hoàn tiền, audit log."""

import re
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import redis
from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import db, passwords, totp
from .audit import AuditLogger, mask_pan
from .config import load_settings
from .rbac import ROLE_PERMISSIONS, has_permission
from .sessions import ANONYMOUS, AUTHENTICATED, PENDING_MFA, SessionStore, sid_hash, ua_hash

settings = load_settings()
redis_client = redis.Redis(
    host=settings.redis_host,
    port=settings.redis_port,
    password=settings.redis_password,
    decode_responses=True,
    socket_timeout=2,
)
store = SessionStore(
    redis_client,
    ttl_by_state={
        ANONYMOUS: settings.idle_timeout,
        PENDING_MFA: settings.pending_mfa_timeout,
        AUTHENTICATED: settings.idle_timeout,
    },
    index_ttl=settings.absolute_timeout + 60,
)
audit_log = AuditLogger(settings.audit_log_path)
db.init_db(settings.db_path)

app = FastAPI(title="ATTMDT Lab 01 - Secure Identity, Session & Authorization")

_CORRELATION_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_PAN_DIGITS_RE = re.compile(r"[0-9]{13,19}")


class ApiError(Exception):
    """Lỗi trả về client dạng {"error": CODE}, không lộ chi tiết nội bộ."""

    def __init__(self, status: int, error: str, clear_cookie: bool = False) -> None:
        super().__init__(error)
        self.status = status
        self.error = error
        self.clear_cookie = clear_cookie


# ---------------------------------------------------------------- hạ tầng request


@app.exception_handler(ApiError)
async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
    response = JSONResponse({"error": exc.error}, status_code=exc.status)
    if exc.clear_cookie:
        _clear_session_cookie(response)
    return response


@app.exception_handler(RequestValidationError)
async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Chỉ trả tên trường lỗi; không trả lại giá trị client gửi (có thể là mật khẩu, số thẻ)."""
    fields = [".".join(str(part) for part in err["loc"][1:]) for err in exc.errors()]
    return JSONResponse({"error": "VALIDATION_ERROR", "fields": fields}, status_code=422)


@app.middleware("http")
async def _correlation_and_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Gắn correlation_id cho mỗi request (nhận từ client nếu hợp lệ) và header an toàn."""
    incoming = request.headers.get("x-correlation-id", "")
    request.state.correlation_id = (
        incoming if _CORRELATION_RE.fullmatch(incoming) else str(uuid.uuid4())
    )
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = request.state.correlation_id
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "-"


def _user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")


def _audit(
    request: Request,
    action: str,
    result: str,
    session: dict[str, str] | None = None,
    object_id: str | None = None,
    presented_sid_hash: str | None = None,
    **details: Any,
) -> None:
    """Ghi audit event; actor và role lấy từ session phía server, không lấy từ input."""
    hashed = session["sid_hash"] if session else presented_sid_hash
    audit_log.write(
        action=action,
        result=result,
        actor_id=int(session["user_id"]) if session and session.get("user_id") else None,
        role=session.get("role") if session else None,
        object_id=object_id,
        source_ip=_client_ip(request),
        correlation_id=request.state.correlation_id,
        session_id_hash=hashed[:16] if hashed else None,
        details=details,
    )


def _set_session_cookie(response: Response, sid: str) -> None:
    """Cookie phiên: HttpOnly, Secure, SameSite=Strict, tiền tố __Host- (Path=/, không Domain)."""
    response.set_cookie(
        settings.cookie_name, sid, httponly=True, secure=True, samesite="strict", path="/"
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        settings.cookie_name, path="/", secure=True, httponly=True, samesite="strict"
    )


# ---------------------------------------------------------------- session & quyền


def current_session(request: Request) -> dict[str, str]:
    """Session đã qua MFA: kiểm tra absolute timeout và dấu hiệu bất thường, rồi gia hạn idle."""
    presented = request.cookies.get(settings.cookie_name)
    session = store.load(presented)
    if session is None or session["state"] != AUTHENTICATED:
        if presented:
            _audit(
                request,
                "SESSION_CHECK",
                "DENIED",
                session,
                presented_sid_hash=sid_hash(presented),
                reason="invalid_or_revoked" if session is None else "mfa_not_completed",
            )
        raise ApiError(401, "NOT_AUTHENTICATED", clear_cookie=session is None)
    if time.time() - float(session["auth_at"]) > settings.absolute_timeout:
        store.destroy(session)
        _audit(request, "SESSION_EXPIRED", "DENIED", session, reason="absolute_timeout_8h")
        raise ApiError(401, "SESSION_EXPIRED", clear_cookie=True)
    if ua_hash(_user_agent(request)) != session["ua_hash"]:
        store.destroy(session)
        _audit(request, "SESSION_ANOMALY", "DENIED", session, reason="user_agent_changed")
        raise ApiError(401, "SESSION_REVOKED", clear_cookie=True)
    store.touch(session)
    return session


def require(permission: str) -> Callable[..., dict[str, str]]:
    """Dependency kiểm tra quyền ở backend; thiếu quyền thì 403 và audit result=DENIED."""

    def dependency(
        request: Request, session: dict[str, str] = Depends(current_session)
    ) -> dict[str, str]:
        if not has_permission(session["role"], permission):
            refund_id = request.path_params.get("refund_id")
            _audit(
                request,
                permission.replace(":", "_").upper(),
                "DENIED",
                session,
                object_id=f"refund:{refund_id}" if refund_id else None,
                reason="missing_permission",
                permission=permission,
            )
            raise ApiError(403, "FORBIDDEN")
        return session

    return dependency


def _check_current_password(
    request: Request, session: dict[str, str], password: str, action: str
) -> None:
    with db.transaction(settings.db_path) as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (int(session["user_id"]),)
        ).fetchone()
    if row is None or not passwords.verify_password(password, row["password_hash"]):
        _audit(request, action, "FAILURE", session, reason="wrong_current_password")
        raise ApiError(401, "INVALID_CREDENTIALS")


def _record_mfa_failure(user_id: int) -> None:
    pipe = redis_client.pipeline(transaction=True)
    pipe.incr(f"mfa_fail:{user_id}")
    pipe.expire(f"mfa_fail:{user_id}", settings.mfa_failure_window)
    pipe.execute()


# ---------------------------------------------------------------- xác thực


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class MfaIn(BaseModel):
    code: str = Field(min_length=1, max_length=10)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class MfaResetIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)


@app.get("/health")
def health() -> dict[str, str]:
    redis_client.ping()
    return {"status": "ok"}


@app.get("/auth/session")
def auth_session(request: Request, response: Response) -> dict[str, str]:
    """Trạng thái phiên hiện tại; chưa có phiên thì cấp phiên ẩn danh."""
    session = store.load(request.cookies.get(settings.cookie_name))
    if session is None:
        _set_session_cookie(response, store.create(ANONYMOUS, _user_agent(request)))
        return {"state": ANONYMOUS}
    return {"state": session["state"]}


@app.post("/auth/login")
def login(body: LoginIn, request: Request, response: Response) -> dict[str, bool]:
    """Bước 1: kiểm tra mật khẩu, cấp Session ID mới ở trạng thái chờ MFA."""
    previous = store.load(request.cookies.get(settings.cookie_name))
    with db.transaction(settings.db_path) as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (body.username,)).fetchone()
    stored_hash = user["password_hash"] if user else passwords.DUMMY_HASH
    if not passwords.verify_password(body.password, stored_hash) or user is None:
        _audit(request, "LOGIN_PASSWORD", "FAILURE", previous, username=body.username)
        raise ApiError(401, "INVALID_CREDENTIALS")
    if previous is not None:
        store.destroy(previous)
    sid = store.create(PENDING_MFA, _user_agent(request), user["id"], user["username"], user["role"])
    _set_session_cookie(response, sid)
    _audit(
        request,
        "LOGIN_PASSWORD",
        "SUCCESS",
        store.load(sid),
        previous_session_id_hash=previous["sid_hash"][:16] if previous else None,
    )
    return {"mfa_required": True}


@app.post("/auth/mfa")
def verify_mfa(body: MfaIn, request: Request, response: Response) -> dict[str, str]:
    """Bước 2: kiểm TOTP, chặn replay bằng Redis SET NX, rồi xoay Session ID."""
    pending = store.load(request.cookies.get(settings.cookie_name))
    if pending is None or pending["state"] != PENDING_MFA:
        raise ApiError(401, "MFA_SESSION_INVALID")
    user_id = int(pending["user_id"])
    if int(redis_client.get(f"mfa_fail:{user_id}") or 0) >= settings.mfa_max_failures:
        store.destroy(pending)
        _audit(request, "MFA_LOCKED", "DENIED", pending)
        raise ApiError(429, "MFA_LOCKED", clear_cookie=True)

    with db.transaction(settings.db_path) as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    step = totp.verify(
        user["totp_secret"],
        body.code,
        time.time(),
        settings.totp_step,
        settings.totp_digits,
        settings.totp_window,
    )
    if step is None:
        _record_mfa_failure(user_id)
        _audit(request, "MFA_VERIFY", "FAILURE", pending, reason="wrong_or_expired_code")
        raise ApiError(401, "MFA_FAILED")

    used_key = f"totp:used:{user_id}:{step}"
    if not redis_client.set(used_key, "1", nx=True, ex=settings.replay_ttl):
        _record_mfa_failure(user_id)
        _audit(request, "REPLAY_DETECTED", "DENIED", pending, time_step=step, redis_key=used_key)
        raise ApiError(401, "REPLAY_DETECTED")

    redis_client.delete(f"mfa_fail:{user_id}")
    store.destroy(pending)
    sid = store.create(
        AUTHENTICATED, _user_agent(request), user["id"], user["username"], user["role"]
    )
    _set_session_cookie(response, sid)
    _audit(
        request,
        "MFA_VERIFY",
        "SUCCESS",
        store.load(sid),
        time_step=step,
        previous_session_id_hash=pending["sid_hash"][:16],
    )
    return {"mfa": "verified", "username": user["username"], "role": user["role"]}


@app.get("/me")
def me(session: dict[str, str] = Depends(current_session)) -> dict[str, Any]:
    return {
        "username": session["username"],
        "role": session["role"],
        "mfa": "verified",
        "permissions": sorted(ROLE_PERMISSIONS.get(session["role"], ())),
    }


@app.post("/auth/logout")
def logout(
    request: Request, response: Response, session: dict[str, str] = Depends(current_session)
) -> dict[str, bool]:
    store.destroy(session)
    _clear_session_cookie(response)
    _audit(request, "LOGOUT", "SUCCESS", session)
    return {"logged_out": True}


@app.post("/auth/password")
def change_password(
    body: PasswordChangeIn,
    request: Request,
    response: Response,
    session: dict[str, str] = Depends(current_session),
) -> dict[str, Any]:
    """Đổi mật khẩu rồi thu hồi mọi session của user (kể cả session hiện tại)."""
    _check_current_password(request, session, body.current_password, "PASSWORD_CHANGE")
    user_id = int(session["user_id"])
    with db.transaction(settings.db_path) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (passwords.hash_password(body.new_password), user_id),
        )
    revoked = store.revoke_all(user_id)
    _clear_session_cookie(response)
    _audit(request, "PASSWORD_CHANGE", "SUCCESS", session, sessions_revoked=revoked)
    return {"password_changed": True, "sessions_revoked": revoked}


@app.post("/auth/mfa/reset")
def reset_mfa(
    body: MfaResetIn,
    request: Request,
    response: Response,
    session: dict[str, str] = Depends(current_session),
) -> dict[str, Any]:
    """Cấp TOTP secret mới (trả một lần để đăng ký lại) và thu hồi mọi session của user."""
    _check_current_password(request, session, body.current_password, "MFA_RESET")
    user_id = int(session["user_id"])
    secret = totp.new_secret()
    with db.transaction(settings.db_path) as conn:
        conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id))
    revoked = store.revoke_all(user_id)
    _clear_session_cookie(response)
    _audit(request, "MFA_RESET", "SUCCESS", session, sessions_revoked=revoked)
    return {
        "mfa_reset": True,
        "sessions_revoked": revoked,
        "otpauth_uri": totp.provisioning_uri(secret, session["username"]),
    }


# ---------------------------------------------------------------- hoàn tiền


class RefundIn(BaseModel):
    # Trường lạ (ví dụ cvv) bị bỏ qua: không lưu, không log.
    model_config = ConfigDict(extra="ignore")

    order_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9-]+$")
    amount: int = Field(gt=0, le=1_000_000_000)
    reason: str = Field(min_length=1, max_length=500)
    card_pan: str | None = Field(default=None, max_length=32)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value = value * 2 - 9 if value * 2 > 9 else value * 2
        total += value
    return total % 10 == 0


def _pan_last4(pan: str) -> str:
    """Kiểm tra số thẻ (13-19 số, Luhn) và chỉ giữ lại 4 số cuối để lưu."""
    digits = pan.replace(" ", "").replace("-", "")
    if not _PAN_DIGITS_RE.fullmatch(digits) or not _luhn_ok(digits):
        raise ApiError(422, "INVALID_PAN")
    return digits[-4:]


def _refund_out(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "order_id": row["order_id"],
        "amount": row["amount"],
        "reason": row["reason"],
        "card": f"**** **** **** {row['pan_last4']}" if row["pan_last4"] else None,
        "status": row["status"],
        "created_by": row["created_by"],
        "approved_by": row["approved_by"],
        "created_at": row["created_at"],
        "approved_at": row["approved_at"],
    }


@app.post("/refunds", status_code=201)
def create_refund(
    body: RefundIn, request: Request, session: dict[str, str] = Depends(require("refund:create"))
) -> dict[str, Any]:
    """CSKH tạo yêu cầu hoàn tiền; DB chỉ lưu 4 số cuối của thẻ, lý do được che số thẻ."""
    last4 = _pan_last4(body.card_pan) if body.card_pan else None
    with db.transaction(settings.db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO refunds (order_id, amount, reason, pan_last4, status, created_by, created_at)"
            " VALUES (?, ?, ?, ?, 'PENDING', ?, ?)",
            (body.order_id, body.amount, mask_pan(body.reason), last4, int(session["user_id"]), db.utcnow()),
        )
        row = conn.execute("SELECT * FROM refunds WHERE id = ?", (cursor.lastrowid,)).fetchone()
    _audit(
        request,
        "REFUND_CREATE",
        "SUCCESS",
        session,
        object_id=f"refund:{row['id']}",
        order_id=body.order_id,
        amount=body.amount,
        card_last4=last4,
        # Lý do là văn bản tự do: bộ lọc audit che số thẻ nếu người dùng gõ vào.
        reason=body.reason,
    )
    return _refund_out(row)


@app.get("/refunds")
def list_refunds(session: dict[str, str] = Depends(require("refund:read"))) -> list[dict[str, Any]]:
    with db.transaction(settings.db_path) as conn:
        rows = conn.execute("SELECT * FROM refunds ORDER BY id").fetchall()
    return [_refund_out(row) for row in rows]


@app.get("/refunds/{refund_id}")
def get_refund(
    refund_id: int, session: dict[str, str] = Depends(require("refund:read"))
) -> dict[str, Any]:
    with db.transaction(settings.db_path) as conn:
        row = conn.execute("SELECT * FROM refunds WHERE id = ?", (refund_id,)).fetchone()
    if row is None:
        raise ApiError(404, "NOT_FOUND")
    return _refund_out(row)


@app.post("/refunds/{refund_id}/approve")
def approve_refund(
    refund_id: int,
    request: Request,
    session: dict[str, str] = Depends(require("refund:approve")),
) -> dict[str, Any]:
    """Kế toán duyệt chi; người duyệt khác người tạo, chỉ duyệt được yêu cầu đang PENDING."""
    approver_id = int(session["user_id"])
    object_id = f"refund:{refund_id}"
    with db.transaction(settings.db_path) as conn:
        row = conn.execute("SELECT * FROM refunds WHERE id = ?", (refund_id,)).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND")
        if row["created_by"] == approver_id:
            _audit(request, "REFUND_APPROVE", "DENIED", session, object_id=object_id,
                   reason="separation_of_duties")
            raise ApiError(403, "SOD_VIOLATION")
        cursor = conn.execute(
            "UPDATE refunds SET status = 'APPROVED', approved_by = ?, approved_at = ?"
            " WHERE id = ? AND status = 'PENDING' AND created_by <> ?",
            (approver_id, db.utcnow(), refund_id, approver_id),
        )
        if cursor.rowcount == 0:
            _audit(request, "REFUND_APPROVE", "FAILURE", session, object_id=object_id,
                   reason="not_pending")
            raise ApiError(409, "INVALID_STATE")
        row = conn.execute("SELECT * FROM refunds WHERE id = ?", (refund_id,)).fetchone()
    _audit(request, "REFUND_APPROVE", "SUCCESS", session, object_id=object_id, amount=row["amount"])
    return _refund_out(row)
