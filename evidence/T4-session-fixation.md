# T4 - Session Fixation

**PASS khi:** SID_before khác SID_after; SID cũ không dùng lại được; cookie HttpOnly, Secure, SameSite

**Kết quả:** PASS


## 1. Lấy SID trước khi login

### Phiên ẩn danh

Request:
```http
GET /auth/session
X-Correlation-ID: T4-01-cf241571
User-Agent: attmdt-lab01-tests/1.0
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=_TgvId...Z9PQ (sha256:db2f84e763aac6d9); HttpOnly; Path=/; SameSite=strict; Secure

{
  "state": "anonymous"
}
```


## 2. Password + MFA, gửi kèm SID_before

### cskh02: bước 1 - password

Request:
```http
POST /auth/login
X-Correlation-ID: T4-02-b790693d
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=_TgvId...Z9PQ (sha256:db2f84e763aac6d9)

{
  "username": "cskh02",
  "password": "***(ẩn)"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=N-gfrF...4fwI (sha256:d57daefc3bf5687c); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa_required": true
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.365+00:00", "action": "LOGIN_PASSWORD", "result": "SUCCESS", "actor_id": 2, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T4-02-b790693d", "session_id_hash": "d57daefc3bf5687c", "details": {"previous_session_id_hash": "db2f84e763aac6d9"}}
```

### cskh02: bước 2 - TOTP

Request:
```http
POST /auth/mfa
X-Correlation-ID: T4-03-c1b72086
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=N-gfrF...4fwI (sha256:d57daefc3bf5687c)

{
  "code": "858853"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=Pk8nCU...CVzs (sha256:ddf824b5d7798b05); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa": "verified",
  "username": "cskh02",
  "role": "CSKH"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.369+00:00", "action": "MFA_VERIFY", "result": "SUCCESS", "actor_id": 2, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T4-03-c1b72086", "session_id_hash": "ddf824b5d7798b05", "details": {"time_step": 59771921, "previous_session_id_hash": "d57daefc3bf5687c"}}
```


## 3. So sánh SID

```text
SID_before (trước login): _TgvId...Z9PQ (sha256:db2f84e763aac6d9)
SID_pending (sau password): N-gfrF...4fwI (sha256:d57daefc3bf5687c)
SID_after  (sau MFA):     Pk8nCU...CVzs (sha256:ddf824b5d7798b05)
```


## 4. Dùng lại SID cũ

### GET /me bằng SID_before

Request:
```http
GET /me
X-Correlation-ID: T4-04-f857d4e1
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=_TgvId...Z9PQ (sha256:db2f84e763aac6d9)
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
{"timestamp": "2026-10-28T03:20:45.372+00:00", "action": "SESSION_CHECK", "result": "DENIED", "actor_id": null, "role": null, "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T4-04-f857d4e1", "session_id_hash": "db2f84e763aac6d9", "details": {"reason": "invalid_or_revoked"}}
```

### GET /me bằng SID_pending

Request:
```http
GET /me
X-Correlation-ID: T4-05-573ea005
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=N-gfrF...4fwI (sha256:d57daefc3bf5687c)
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
{"timestamp": "2026-10-28T03:20:45.374+00:00", "action": "SESSION_CHECK", "result": "DENIED", "actor_id": null, "role": null, "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T4-05-573ea005", "session_id_hash": "d57daefc3bf5687c", "details": {"reason": "invalid_or_revoked"}}
```

### GET /me bằng SID_after

Request:
```http
GET /me
X-Correlation-ID: T4-06-16f2ae6f
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


## 5. Session trong Redis (chỉ lưu hash của SID)

```text
> HGETALL sess:ddf824b5d7798b0504eb2811fd1f34d1a2fd4c8e57ab9f8fb803e3e8584dd052
{
  "state": "authenticated",
  "created_at": "1793157645.3692124",
  "ua_hash": "005a618edb7572655b60f2f371b193d7",
  "user_id": "2",
  "username": "cskh02",
  "role": "CSKH",
  "auth_at": "1793157645.3692124"
}
> TTL sess:ddf824b5d7798b0504eb2811fd1f34d1a2fd4c8e57ab9f8fb803e3e8584dd052
(integer) 900
```

