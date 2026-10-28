# T8 - Session revocation

**PASS khi:** Request bằng session đã bị revoke nhận 401/403

**Kết quả:** PASS


## a. Logout

### Trước logout

Request:
```http
GET /me
X-Correlation-ID: T8-01-b01dde13
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=Pk8nCU...CVzs (sha256:ddf824b5d7798b05)
```

Response:
```http
HTTP 200

{
  "username": "cskh02",
  "role": "CSKH",
  "mfa": "verified",
  "permissions": [
    "refund:create",
    "refund:read"
  ]
}
```

### Logout

Request:
```http
POST /auth/logout
X-Correlation-ID: T8-02-375044ff
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=Pk8nCU...CVzs (sha256:ddf824b5d7798b05)
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=""; expires=Wed, 28 Oct 2026 03:20:45 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure

{
  "logged_out": true
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.503+00:00", "action": "LOGOUT", "result": "SUCCESS", "actor_id": 2, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-02-375044ff", "session_id_hash": "ddf824b5d7798b05", "details": {}}
```

### Sau logout, dùng session cũ

Request:
```http
GET /me
X-Correlation-ID: T8-03-13e7ea45
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=Pk8nCU...CVzs (sha256:ddf824b5d7798b05)
```

Response:
```http
HTTP 401
Set-Cookie: __Host-sid=""; expires=Wed, 28 Oct 2026 03:20:45 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure

{
  "error": "NOT_AUTHENTICATED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.505+00:00", "action": "SESSION_CHECK", "result": "DENIED", "actor_id": null, "role": null, "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-03-13e7ea45", "session_id_hash": "ddf824b5d7798b05", "details": {"reason": "invalid_or_revoked"}}
```


## b. Đổi mật khẩu: hủy toàn bộ session của user (bonus)

### ketoan01: bước 1 - password

Request:
```http
POST /auth/login
X-Correlation-ID: T8-04-6699d01d
User-Agent: attmdt-lab01-tests/1.0

{
  "username": "ketoan01",
  "password": "***(ẩn)"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=E2Higc...XKLo (sha256:188f35503cd01b0e); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa_required": true
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.544+00:00", "action": "LOGIN_PASSWORD", "result": "SUCCESS", "actor_id": 3, "role": "KE_TOAN", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-04-6699d01d", "session_id_hash": "188f35503cd01b0e", "details": {"previous_session_id_hash": null}}
```

### ketoan01: bước 2 - TOTP

Request:
```http
POST /auth/mfa
X-Correlation-ID: T8-05-46fbc2ec
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=E2Higc...XKLo (sha256:188f35503cd01b0e)

{
  "code": "217826"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=7jDUyt...aMRs (sha256:9e0a6776f2aa64e1); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa": "verified",
  "username": "ketoan01",
  "role": "KE_TOAN"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:00.204+00:00", "action": "MFA_VERIFY", "result": "SUCCESS", "actor_id": 3, "role": "KE_TOAN", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-05-46fbc2ec", "session_id_hash": "9e0a6776f2aa64e1", "details": {"time_step": 59771922, "previous_session_id_hash": "188f35503cd01b0e"}}
```

### ketoan01: đổi mật khẩu (session thứ 2)

Request:
```http
POST /auth/password
X-Correlation-ID: T8-06-b34e72f2
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=7jDUyt...aMRs (sha256:9e0a6776f2aa64e1)

{
  "current_password": "***(ẩn)",
  "new_password": "***(ẩn)"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=""; expires=Wed, 28 Oct 2026 03:21:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure

{
  "password_changed": true,
  "sessions_revoked": 2
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:00.288+00:00", "action": "PASSWORD_CHANGE", "result": "SUCCESS", "actor_id": 3, "role": "KE_TOAN", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-06-b34e72f2", "session_id_hash": "9e0a6776f2aa64e1", "details": {"sessions_revoked": 2}}
```

### Sau đổi mật khẩu, session 1 (từ T6)

Request:
```http
GET /me
X-Correlation-ID: T8-07-846b10ed
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=Dpsaav...P3l4 (sha256:c3babf6f0dcdff2f)
```

Response:
```http
HTTP 401
Set-Cookie: __Host-sid=""; expires=Wed, 28 Oct 2026 03:21:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure

{
  "error": "NOT_AUTHENTICATED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:00.290+00:00", "action": "SESSION_CHECK", "result": "DENIED", "actor_id": null, "role": null, "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-07-846b10ed", "session_id_hash": "c3babf6f0dcdff2f", "details": {"reason": "invalid_or_revoked"}}
```

### Sau đổi mật khẩu, session 2

Request:
```http
GET /me
X-Correlation-ID: T8-08-1f8ac2dc
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=7jDUyt...aMRs (sha256:9e0a6776f2aa64e1)
```

Response:
```http
HTTP 401
Set-Cookie: __Host-sid=""; expires=Wed, 28 Oct 2026 03:21:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure

{
  "error": "NOT_AUTHENTICATED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:00.292+00:00", "action": "SESSION_CHECK", "result": "DENIED", "actor_id": null, "role": null, "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-08-1f8ac2dc", "session_id_hash": "9e0a6776f2aa64e1", "details": {"reason": "invalid_or_revoked"}}
```


## c. Reset MFA

### cskh01: reset MFA

Request:
```http
POST /auth/mfa/reset
X-Correlation-ID: T8-09-7ae70c40
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=4gQmtb...TZGQ (sha256:e6c214607b4707c7)

{
  "current_password": "***(ẩn)"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=""; expires=Wed, 28 Oct 2026 03:21:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure

{
  "mfa_reset": true,
  "sessions_revoked": 3,
  "otpauth_uri": "otpauth://totp/ATTMDT-Lab01%3Acskh01?secret=***(ẩn)&issuer=ATTMDT-Lab01&algorithm=SHA1&digits=6&period=30"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:00.334+00:00", "action": "MFA_RESET", "result": "SUCCESS", "actor_id": 1, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-09-7ae70c40", "session_id_hash": "e6c214607b4707c7", "details": {"sessions_revoked": 3}}
```

### Sau reset MFA, dùng session cũ

Request:
```http
GET /me
X-Correlation-ID: T8-10-0a1ccd83
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=4gQmtb...TZGQ (sha256:e6c214607b4707c7)
```

Response:
```http
HTTP 401
Set-Cookie: __Host-sid=""; expires=Wed, 28 Oct 2026 03:21:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure

{
  "error": "NOT_AUTHENTICATED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:00.337+00:00", "action": "SESSION_CHECK", "result": "DENIED", "actor_id": null, "role": null, "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-10-0a1ccd83", "session_id_hash": "e6c214607b4707c7", "details": {"reason": "invalid_or_revoked"}}
```


## d. Phát hiện bất thường: session bị dùng từ client khác (User-Agent đổi)

### admin01: bước 1 - password

Request:
```http
POST /auth/login
X-Correlation-ID: T8-11-70247438
User-Agent: attmdt-lab01-tests/1.0

{
  "username": "admin01",
  "password": "***(ẩn)"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=7fRfW2...LlrA (sha256:87942c152cca4d6d); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa_required": true
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:00.374+00:00", "action": "LOGIN_PASSWORD", "result": "SUCCESS", "actor_id": 4, "role": "ADMIN", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-11-70247438", "session_id_hash": "87942c152cca4d6d", "details": {"previous_session_id_hash": null}}
```

### admin01: bước 2 - TOTP

Request:
```http
POST /auth/mfa
X-Correlation-ID: T8-12-13d3989c
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=7fRfW2...LlrA (sha256:87942c152cca4d6d)

{
  "code": "201632"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=64s3Fr...Tz4s (sha256:5c763ed512ae5003); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa": "verified",
  "username": "admin01",
  "role": "ADMIN"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:00.378+00:00", "action": "MFA_VERIFY", "result": "SUCCESS", "actor_id": 4, "role": "ADMIN", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-12-13d3989c", "session_id_hash": "5c763ed512ae5003", "details": {"time_step": 59771922, "previous_session_id_hash": "87942c152cca4d6d"}}
```

### Cùng session, User-Agent lạ

Request:
```http
GET /me
X-Correlation-ID: T8-13-22cb89d6
User-Agent: Mozilla/5.0 (attacker)
Cookie: __Host-sid=64s3Fr...Tz4s (sha256:5c763ed512ae5003)
```

Response:
```http
HTTP 401
Set-Cookie: __Host-sid=""; expires=Wed, 28 Oct 2026 03:21:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure

{
  "error": "SESSION_REVOKED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:00.381+00:00", "action": "SESSION_ANOMALY", "result": "DENIED", "actor_id": 4, "role": "ADMIN", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-13-22cb89d6", "session_id_hash": "5c763ed512ae5003", "details": {"reason": "user_agent_changed"}}
```

### Quay lại User-Agent gốc

Request:
```http
GET /me
X-Correlation-ID: T8-14-fcc4f6c8
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=64s3Fr...Tz4s (sha256:5c763ed512ae5003)
```

Response:
```http
HTTP 401
Set-Cookie: __Host-sid=""; expires=Wed, 28 Oct 2026 03:21:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure

{
  "error": "NOT_AUTHENTICATED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:00.383+00:00", "action": "SESSION_CHECK", "result": "DENIED", "actor_id": null, "role": null, "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T8-14-fcc4f6c8", "session_id_hash": "5c763ed512ae5003", "details": {"reason": "invalid_or_revoked"}}
```

