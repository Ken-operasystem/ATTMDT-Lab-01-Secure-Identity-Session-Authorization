# T2 - Replay OTP

**PASS khi:** 401/403; event REPLAY_DETECTED; Redis còn key của time-step đã dùng

**Kết quả:** PASS


## Gửi lại đúng OTP của T1

OTP của T1: `417417` (time-step 59771921). Tại thời điểm gửi lại, OTP này vẫn nằm trong cửa sổ hợp lệ: **True**.

### cskh01: bước 1 - password

Request:
```http
POST /auth/login
X-Correlation-ID: T2-01-e65734e0
User-Agent: attmdt-lab01-tests/1.0

{
  "username": "cskh01",
  "password": "***(ẩn)"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=Iuuvgh...Q6xY (sha256:51a7ef21cc1dfcdd); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa_required": true
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.253+00:00", "action": "LOGIN_PASSWORD", "result": "SUCCESS", "actor_id": 1, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T2-01-e65734e0", "session_id_hash": "51a7ef21cc1dfcdd", "details": {"previous_session_id_hash": null}}
```

### cskh01: gửi lại OTP của T1

Request:
```http
POST /auth/mfa
X-Correlation-ID: T2-02-d6640d49
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=Iuuvgh...Q6xY (sha256:51a7ef21cc1dfcdd)

{
  "code": "417417"
}
```

Response:
```http
HTTP 401

{
  "error": "REPLAY_DETECTED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.258+00:00", "action": "REPLAY_DETECTED", "result": "DENIED", "actor_id": 1, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T2-02-d6640d49", "session_id_hash": "51a7ef21cc1dfcdd", "details": {"time_step": 59771921, "redis_key": "totp:used:1:59771921"}}
```


## Redis: key time-step đã dùng (ghi bằng SET NX EX)

```text
> GET totp:used:1:59771921
"1"
> TTL totp:used:1:59771921
(integer) 120
```

