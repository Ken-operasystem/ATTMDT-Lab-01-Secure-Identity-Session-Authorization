# T1 - TOTP hợp lệ

**PASS khi:** HTTP 200; MFA state = verified; log auth success

**Kết quả:** PASS


## Login bằng password, nhập OTP đúng lần đầu

### cskh01: bước 1 - password

Request:
```http
POST /auth/login
X-Correlation-ID: T1-01-0421d785
User-Agent: attmdt-lab01-tests/1.0

{
  "username": "cskh01",
  "password": "***(ẩn)"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=qMIkIL...O6Qg (sha256:25700d8a77e62b08); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa_required": true
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.197+00:00", "action": "LOGIN_PASSWORD", "result": "SUCCESS", "actor_id": 1, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T1-01-0421d785", "session_id_hash": "25700d8a77e62b08", "details": {"previous_session_id_hash": null}}
```

### cskh01: bước 2 - TOTP đúng

Request:
```http
POST /auth/mfa
X-Correlation-ID: T1-02-6c58ce3c
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=qMIkIL...O6Qg (sha256:25700d8a77e62b08)

{
  "code": "417417"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=4gQmtb...TZGQ (sha256:e6c214607b4707c7); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa": "verified",
  "username": "cskh01",
  "role": "CSKH"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.204+00:00", "action": "MFA_VERIFY", "result": "SUCCESS", "actor_id": 1, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T1-02-6c58ce3c", "session_id_hash": "e6c214607b4707c7", "details": {"time_step": 59771921, "previous_session_id_hash": "25700d8a77e62b08"}}
```

### Dùng session sau MFA

Request:
```http
GET /me
X-Correlation-ID: T1-03-da20e13f
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=4gQmtb...TZGQ (sha256:e6c214607b4707c7)
```

Response:
```http
HTTP 200

{
  "username": "cskh01",
  "role": "CSKH",
  "mfa": "verified",
  "permissions": [
    "refund:create",
    "refund:read"
  ]
}
```

