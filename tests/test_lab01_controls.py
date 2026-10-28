"""T1-T9: test chủ động bằng request thật vào app đang chạy; mỗi test ghi evidence/Tn-*.md.

Các test chạy tuần tự và dùng chung session qua STATE (T1 tạo session CSKH dùng ở T5-T8).
"""

import json
import re
import secrets
import shutil
import time

from lab01 import totp
from lab_client import (
    AUDIT_LOG,
    EVIDENCE_DIR,
    PASSWORDS,
    SEEN_SIDS,
    TOTP_SECRETS,
    USER_AGENT,
    Api,
    cookie_sid,
    credentials,
    fresh_code,
    login,
    password_step,
    redis_client,
    seed_users,
    session_key,
    set_cookie_headers,
    show_sid,
)

STATE: dict[str, object] = {}
TEST_PAN = "4111 1111 1111 1111"  # số thẻ test Visa công khai, không phải thẻ thật
TEST_CVV = "737"


def test_t1_totp_valid(evidence):
    ev = evidence("T1", "totp-valid", "TOTP hợp lệ", "HTTP 200; MFA state = verified; log auth success")
    api = Api(ev)
    ev.section("Login bằng password, nhập OTP đúng lần đầu")
    pending = password_step(api, "cskh01")
    step, code = fresh_code("cskh01")
    r = api.call("POST", "/auth/mfa", label="cskh01: bước 2 - TOTP đúng", sid=pending, body={"code": code})
    assert r.status_code == 200
    assert r.json()["mfa"] == "verified"
    assert ("MFA_VERIFY", "SUCCESS") in api.actions()
    sid = cookie_sid(r)
    r = api.call("GET", "/me", label="Dùng session sau MFA", sid=sid)
    assert r.status_code == 200 and r.json()["mfa"] == "verified"
    STATE.update(cskh01_sid=sid, t1_code=code, t1_step=step)


def test_t2_replay_otp(evidence):
    ev = evidence(
        "T2", "replay-otp", "Replay OTP",
        "401/403; event REPLAY_DETECTED; Redis còn key của time-step đã dùng",
    )
    api = Api(ev)
    _, secret = credentials("cskh01")
    code = STATE["t1_code"]
    still_valid = totp.verify(secret, code, time.time()) is not None
    ev.section("Gửi lại đúng OTP của T1")
    ev.text(f"OTP của T1: `{code}` (time-step {STATE['t1_step']}). "
            f"Tại thời điểm gửi lại, OTP này vẫn nằm trong cửa sổ hợp lệ: **{still_valid}**.")
    assert still_valid
    pending = password_step(api, "cskh01")
    r = api.call("POST", "/auth/mfa", label="cskh01: gửi lại OTP của T1", sid=pending, body={"code": code})
    assert r.status_code == 401
    assert r.json()["error"] == "REPLAY_DETECTED"
    assert cookie_sid(r) is None  # không cấp session mới
    assert ("REPLAY_DETECTED", "DENIED") in api.actions()

    key = api.last_audit[0]["details"]["redis_key"]
    rds = redis_client()
    value, ttl = rds.get(key), rds.ttl(key)
    ev.section("Redis: key time-step đã dùng (ghi bằng SET NX EX)")
    ev.block(f"> GET {key}\n\"{value}\"\n> TTL {key}\n(integer) {ttl}", "text")
    assert value == "1" and 0 < ttl <= 120


def test_t3_wrong_or_expired_otp(evidence):
    ev = evidence(
        "T3", "wrong-expired-otp", "OTP sai / hết hạn",
        "Bị từ chối; không tạo session đặc quyền; log auth failure",
    )
    api = Api(ev)
    _, secret = credentials("cskh01")
    key = totp.decode_secret(secret)
    current = totp.time_step(time.time())
    valid_now = {totp.hotp(key, s) for s in range(current - 1, current + 3)}
    wrong = next(c for c in ("000000", "111111", "123456", "999999") if c not in valid_now)
    expired = totp.hotp(key, current - 3)  # 90 giây trước, ngoài cửa sổ ±1 step
    assert expired not in valid_now

    pending = password_step(api, "cskh01")
    ev.section("OTP sai")
    r = api.call("POST", "/auth/mfa", label=f"cskh01: OTP sai {wrong}", sid=pending, body={"code": wrong})
    assert r.status_code == 401 and r.json()["error"] == "MFA_FAILED"
    assert cookie_sid(r) is None
    assert ("MFA_VERIFY", "FAILURE") in api.actions()

    ev.section("OTP hết hạn (time-step hiện tại - 3, tức khoảng 90 giây trước)")
    r = api.call("POST", "/auth/mfa", label=f"cskh01: OTP hết hạn {expired}", sid=pending, body={"code": expired})
    assert r.status_code == 401 and r.json()["error"] == "MFA_FAILED"
    assert cookie_sid(r) is None
    assert ("MFA_VERIFY", "FAILURE") in api.actions()

    ev.section("Session chờ MFA không có quyền gọi API")
    for path in ("/me", "/refunds"):
        r = api.call("GET", path, label=f"GET {path} bằng session chưa qua MFA", sid=pending)
        assert r.status_code == 401


def test_t4_session_fixation(evidence):
    ev = evidence(
        "T4", "session-fixation", "Session Fixation",
        "SID_before khác SID_after; SID cũ không dùng lại được; cookie HttpOnly, Secure, SameSite",
    )
    api = Api(ev)
    ev.section("1. Lấy SID trước khi login")
    r = api.call("GET", "/auth/session", label="Phiên ẩn danh")
    sid_before = cookie_sid(r)
    assert r.status_code == 200 and sid_before

    ev.section("2. Password + MFA, gửi kèm SID_before")
    pending = password_step(api, "cskh02", sid=sid_before)
    _, code = fresh_code("cskh02")
    r = api.call("POST", "/auth/mfa", label="cskh02: bước 2 - TOTP", sid=pending, body={"code": code})
    assert r.status_code == 200
    sid_after = cookie_sid(r)
    cookie_header = set_cookie_headers(r)[0]

    ev.section("3. So sánh SID")
    ev.block(
        f"SID_before (trước login): {show_sid(sid_before)}\n"
        f"SID_pending (sau password): {show_sid(pending)}\n"
        f"SID_after  (sau MFA):     {show_sid(sid_after)}",
        "text",
    )
    assert len({sid_before, pending, sid_after}) == 3
    flags = cookie_header.lower()
    for flag in ("httponly", "secure", "samesite=strict", "path=/"):
        assert flag in flags, flag

    ev.section("4. Dùng lại SID cũ")
    for label, old in (("SID_before", sid_before), ("SID_pending", pending)):
        r = api.call("GET", "/me", label=f"GET /me bằng {label}", sid=old)
        assert r.status_code == 401
    r = api.call("GET", "/me", label="GET /me bằng SID_after", sid=sid_after)
    assert r.status_code == 200

    ev.section("5. Session trong Redis (chỉ lưu hash của SID)")
    rds = redis_client()
    key = session_key(sid_after)
    data = rds.hgetall(key)
    ttl = rds.ttl(key)
    ev.block(f"> HGETALL {key}\n{json.dumps(data, indent=2)}\n> TTL {key}\n(integer) {ttl}", "text")
    assert data["state"] == "authenticated" and 890 <= ttl <= 900
    STATE["cskh02_sid"] = sid_after


def test_t5_rbac_bypass(evidence):
    ev = evidence("T5", "rbac-bypass", "RBAC bypass", "403; audit result=DENIED")
    api = Api(ev)
    sid = STATE["cskh01_sid"]
    ev.section("CSKH tạo yêu cầu hoàn tiền (hợp lệ)")
    r = api.call("POST", "/refunds", label="cskh01: tạo refund", sid=sid,
                 body={"order_id": "ORD-T5-001", "amount": 150000, "reason": "Khách trả hàng"})
    assert r.status_code == 201
    refund_id = r.json()["id"]

    ev.section("CSKH gọi thẳng API approve (không qua UI)")
    r = api.call("POST", f"/refunds/{refund_id}/approve", label="cskh01: approve refund", sid=sid)
    assert r.status_code == 403 and r.json()["error"] == "FORBIDDEN"
    assert ("REFUND_APPROVE", "DENIED") in api.actions()
    assert api.last_audit[0]["role"] == "CSKH"

    r = api.call("GET", f"/refunds/{refund_id}", label="Refund vẫn PENDING", sid=sid)
    assert r.json()["status"] == "PENDING"


def test_t6_valid_flow(evidence):
    ev = evidence(
        "T6", "valid-flow", "Luồng hợp lệ",
        "CSKH tạo và Kế toán approve thành công đúng role; 2 audit events",
    )
    api = Api(ev)
    ev.section("1. CSKH tạo yêu cầu hoàn tiền")
    r = api.call("POST", "/refunds", label="cskh01: tạo refund", sid=STATE["cskh01_sid"],
                 body={"order_id": "ORD-T6-001", "amount": 320000, "reason": "Giao sai mẫu"})
    assert r.status_code == 201
    assert ("REFUND_CREATE", "SUCCESS") in api.actions()
    refund_id = r.json()["id"]

    ev.section("2. Kế toán đăng nhập và duyệt")
    sid_k = login(api, "ketoan01")
    r = api.call("POST", f"/refunds/{refund_id}/approve", label="ketoan01: approve refund", sid=sid_k)
    assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    assert ("REFUND_APPROVE", "SUCCESS") in api.actions()

    ev.section("3. Kiểm tra thêm: không duyệt lại được, Kế toán không tạo được refund")
    r = api.call("POST", f"/refunds/{refund_id}/approve", label="ketoan01: approve lần 2", sid=sid_k)
    assert r.status_code == 409
    r = api.call("POST", "/refunds", label="ketoan01: thử tạo refund", sid=sid_k,
                 body={"order_id": "ORD-T6-002", "amount": 1000, "reason": "SoD"})
    assert r.status_code == 403
    STATE["ketoan01_sid"] = sid_k


def test_t7_log_masking(evidence):
    ev = evidence(
        "T7", "log-masking", "Log masking",
        "Log không có CVV hay full PAN; PAN chỉ còn last-4",
    )
    api = Api(ev)
    ev.section("Gửi PAN và CVV vào luồng tạo refund")
    ev.text(f"Dữ liệu test: PAN `{TEST_PAN}` (thẻ test Visa), CVV `{TEST_CVV}`; "
            "PAN được gửi ở cả trường card_pan và trong lý do (văn bản tự do).")
    body = {
        "order_id": "ORD-T7-001",
        "amount": 250000,
        "reason": f"Hoàn về thẻ {TEST_PAN} theo yêu cầu khách",
        "card_pan": TEST_PAN,
        "cvv": TEST_CVV,
    }
    r = api.call("POST", "/refunds", label="cskh01: tạo refund có PAN/CVV", sid=STATE["cskh01_sid"], body=body)
    assert r.status_code == 201
    out = r.json()
    assert out["card"] == "**** **** **** 1111"
    assert "1111 1111 1111" not in out["reason"] and "cvv" not in out

    line = json.dumps(api.last_audit, ensure_ascii=False)
    full_pan = TEST_PAN.replace(" ", "")
    assert full_pan not in line and TEST_PAN not in line
    assert "************1111" in line
    details = api.last_audit[0]["details"]
    assert "cvv" not in details and TEST_CVV not in json.dumps(details)
    ev.section("Kết luận")
    ev.text("Audit log ở trên: card_last4 = 1111, PAN trong lý do bị che còn `************1111`, "
            "không có trường cvv. API trả về và DB chỉ giữ 4 số cuối (cột pan_last4).")


def test_t8_session_revocation(evidence):
    ev = evidence(
        "T8", "session-revocation", "Session revocation",
        "Request bằng session đã bị revoke nhận 401/403",
    )
    api = Api(ev)

    ev.section("a. Logout")
    sid = STATE["cskh02_sid"]
    assert api.call("GET", "/me", label="Trước logout", sid=sid).status_code == 200
    r = api.call("POST", "/auth/logout", label="Logout", sid=sid)
    assert r.status_code == 200 and ("LOGOUT", "SUCCESS") in api.actions()
    assert api.call("GET", "/me", label="Sau logout, dùng session cũ", sid=sid).status_code == 401

    ev.section("b. Đổi mật khẩu: hủy toàn bộ session của user (bonus)")
    sid_k1 = STATE["ketoan01_sid"]
    sid_k2 = login(api, "ketoan01")
    old_password, _ = credentials("ketoan01")
    new_password = secrets.token_urlsafe(18)
    r = api.call("POST", "/auth/password", label="ketoan01: đổi mật khẩu (session thứ 2)", sid=sid_k2,
                 body={"current_password": old_password, "new_password": new_password})
    assert r.status_code == 200 and r.json()["sessions_revoked"] >= 2
    PASSWORDS["ketoan01"] = new_password
    for label, old in (("session 1 (từ T6)", sid_k1), ("session 2", sid_k2)):
        assert api.call("GET", "/me", label=f"Sau đổi mật khẩu, {label}", sid=old).status_code == 401

    ev.section("c. Reset MFA")
    sid = STATE["cskh01_sid"]
    password, _ = credentials("cskh01")
    r = api.call("POST", "/auth/mfa/reset", label="cskh01: reset MFA", sid=sid,
                 body={"current_password": password})
    assert r.status_code == 200 and ("MFA_RESET", "SUCCESS") in api.actions()
    TOTP_SECRETS["cskh01"] = re.search(r"secret=([A-Z2-7]+)", r.json()["otpauth_uri"]).group(1)
    assert api.call("GET", "/me", label="Sau reset MFA, dùng session cũ", sid=sid).status_code == 401

    ev.section("d. Phát hiện bất thường: session bị dùng từ client khác (User-Agent đổi)")
    sid = login(api, "admin01")
    r = api.call("GET", "/me", label="Cùng session, User-Agent lạ", sid=sid,
                 user_agent="Mozilla/5.0 (attacker)")
    assert r.status_code == 401 and ("SESSION_ANOMALY", "DENIED") in api.actions()
    r = api.call("GET", "/me", label="Quay lại User-Agent gốc", sid=sid, user_agent=USER_AGENT)
    assert r.status_code == 401


def test_t9_session_timeouts(evidence):
    ev = evidence(
        "T9", "session-timeouts", "Idle 15 phút / absolute 8 giờ (bổ sung kỹ thuật 3)",
        "Session quá idle timeout hoặc quá 8 giờ kể từ MFA nhận 401",
    )
    api = Api(ev)
    rds = redis_client()

    ev.section("a. Idle timeout 15 phút = TTL của key session, gia hạn mỗi request")
    sid = login(api, "cskh02")
    key = session_key(sid)
    time.sleep(2)
    ttl_before = rds.ttl(key)
    assert api.call("GET", "/me", label="Request giữa phiên", sid=sid).status_code == 200
    ttl_after = rds.ttl(key)
    ev.block(f"TTL trước request: {ttl_before}\nTTL sau request (đã gia hạn): {ttl_after}", "text")
    assert ttl_before < ttl_after <= 900
    ev.text("Giả lập 15 phút không hoạt động: rút TTL còn 1 giây (`EXPIRE key 1`), chờ 2 giây.")
    rds.expire(key, 1)
    time.sleep(2)
    assert api.call("GET", "/me", label="Sau idle timeout", sid=sid).status_code == 401

    ev.section("b. Absolute timeout 8 giờ tính từ lúc qua MFA")
    sid = login(api, "admin01")
    key = session_key(sid)
    rds.hset(key, "auth_at", str(time.time() - 8 * 3600 - 1))
    ev.text("Giả lập phiên đã sống quá 8 giờ: đặt `auth_at` của session về 8 giờ 1 giây trước.")
    r = api.call("GET", "/me", label="Sau absolute timeout", sid=sid)
    assert r.status_code == 401 and r.json()["error"] == "SESSION_EXPIRED"
    assert ("SESSION_EXPIRED", "DENIED") in api.actions()


def test_t7b_full_audit_log_scan(evidence):
    ev = evidence(
        "T7b", "audit-log-scan", "Quét toàn bộ audit log sau T1-T9",
        "Không có password, TOTP secret, raw session ID, full PAN hay CVV trong log",
    )
    text = AUDIT_LOG.read_text(encoding="utf-8")
    passwords = {credentials(u)[0] for u in seed_users()} | set(PASSWORDS.values())
    totp_secrets = set(TOTP_SECRETS.values())
    for user in seed_users():
        totp_secrets.add(credentials(user)[1])
    checks = {
        "Mật khẩu (seed + mật khẩu mới đổi ở T8)": passwords,
        "TOTP secret (seed + secret mới ở T8)": totp_secrets,
        "Session ID đầy đủ đã cấp trong T1-T9": set(SEEN_SIDS),
        "Full PAN": {TEST_PAN, TEST_PAN.replace(" ", "")},
        "Trường cvv": {'"cvv"'},
    }
    rows = ["| Loại dữ liệu | Số giá trị kiểm | Số lần xuất hiện trong log |", "|---|---|---|"]
    total = 0
    for label, values in checks.items():
        hits = sum(text.count(v) for v in values)
        total += hits
        rows.append(f"| {label} | {len(values)} | {hits} |")
    ev.section(f"Kết quả quét {AUDIT_LOG.name} ({len(text.splitlines())} dòng)")
    ev.lines += rows + [""]
    ev.text("Toàn bộ audit log của lần chạy này: [audit-full.log](audit-full.log).")
    shutil.copyfile(AUDIT_LOG, EVIDENCE_DIR / "audit-full.log")
    assert total == 0
