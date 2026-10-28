# T3 - OTP sai / hết hạn

**PASS khi:** Bị từ chối; không tạo session đặc quyền; log auth failure

**Kết quả:** PASS

### cskh01: bước 1 - password

Request:
```http
POST /auth/login
X-Correlation-ID: T3-01-14257463
User-Agent: attmdt-lab01-tests/1.0

{
  "username": "cskh01",
  "password": "***(ẩn)"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=pmEG7C...BmYo (sha256:7231438307e2c862); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa_required": true
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.307+00:00", "action": "LOGIN_PASSWORD", "result": "SUCCESS", "actor_id": 1, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T3-01-14257463", "session_id_hash": "7231438307e2c862", "details": {"previous_session_id_hash": null}}
```


## OTP sai

### cskh01: OTP sai 000000

Request:
```http
POST /auth/mfa
X-Correlation-ID: T3-02-ed05b370
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=pmEG7C...BmYo (sha256:7231438307e2c862)

{
  "code": "000000"
}
```

Response:
```http
HTTP 401

{
  "error": "MFA_FAILED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.312+00:00", "action": "MFA_VERIFY", "result": "FAILURE", "actor_id": 1, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T3-02-ed05b370", "session_id_hash": "7231438307e2c862", "details": {"reason": "wrong_or_expired_code"}}
```


## OTP hết hạn (time-step hiện tại - 3, tức khoảng 90 giây trước)

### cskh01: OTP hết hạn 557539

Request:
```http
POST /auth/mfa
X-Correlation-ID: T3-03-378abc11
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=pmEG7C...BmYo (sha256:7231438307e2c862)

{
  "code": "557539"
}
```

Response:
```http
HTTP 401

{
  "error": "MFA_FAILED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.315+00:00", "action": "MFA_VERIFY", "result": "FAILURE", "actor_id": 1, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T3-03-378abc11", "session_id_hash": "7231438307e2c862", "details": {"reason": "wrong_or_expired_code"}}
```


## Session chờ MFA không có quyền gọi API

### GET /me bằng session chưa qua MFA

Request:
```http
GET /me
X-Correlation-ID: T3-04-e456091a
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=pmEG7C...BmYo (sha256:7231438307e2c862)
```

Response:
```http
HTTP 401

{
  "error": "NOT_AUTHENTICATED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.317+00:00", "action": "SESSION_CHECK", "result": "DENIED", "actor_id": 1, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T3-04-e456091a", "session_id_hash": "7231438307e2c862", "details": {"reason": "mfa_not_completed"}}
```

### GET /refunds bằng session chưa qua MFA

Request:
```http
GET /refunds
X-Correlation-ID: T3-05-90c9ef3e
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=pmEG7C...BmYo (sha256:7231438307e2c862)
```

Response:
```http
HTTP 401

{
  "error": "NOT_AUTHENTICATED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.319+00:00", "action": "SESSION_CHECK", "result": "DENIED", "actor_id": 1, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T3-05-90c9ef3e", "session_id_hash": "7231438307e2c862", "details": {"reason": "mfa_not_completed"}}
```

