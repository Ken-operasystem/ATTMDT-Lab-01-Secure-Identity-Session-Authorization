# T9 - Idle 15 phút / absolute 8 giờ (bổ sung kỹ thuật 3)

**PASS khi:** Session quá idle timeout hoặc quá 8 giờ kể từ MFA nhận 401

**Kết quả:** PASS


## a. Idle timeout 15 phút = TTL của key session, gia hạn mỗi request

### cskh02: bước 1 - password

Request:
```http
POST /auth/login
X-Correlation-ID: T9-01-28ab29bf
User-Agent: attmdt-lab01-tests/1.0

{
  "username": "cskh02",
  "password": "***(ẩn)"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=5mNVn9...MHGw (sha256:0b9bcdee8d6f4e03); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa_required": true
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:00.426+00:00", "action": "LOGIN_PASSWORD", "result": "SUCCESS", "actor_id": 2, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T9-01-28ab29bf", "session_id_hash": "0b9bcdee8d6f4e03", "details": {"previous_session_id_hash": null}}
```

### cskh02: bước 2 - TOTP

Request:
```http
POST /auth/mfa
X-Correlation-ID: T9-02-67dfcaf3
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=5mNVn9...MHGw (sha256:0b9bcdee8d6f4e03)

{
  "code": "272567"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=AKnXZs...r-Vg (sha256:d886262350adad50); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa": "verified",
  "username": "cskh02",
  "role": "CSKH"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:00.431+00:00", "action": "MFA_VERIFY", "result": "SUCCESS", "actor_id": 2, "role": "CSKH", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T9-02-67dfcaf3", "session_id_hash": "d886262350adad50", "details": {"time_step": 59771922, "previous_session_id_hash": "0b9bcdee8d6f4e03"}}
```

### Request giữa phiên

Request:
```http
GET /me
X-Correlation-ID: T9-03-a63ab64a
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=AKnXZs...r-Vg (sha256:d886262350adad50)
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

```text
TTL trước request: 898
TTL sau request (đã gia hạn): 900
```

Giả lập 15 phút không hoạt động: rút TTL còn 1 giây (`EXPIRE key 1`), chờ 2 giây.

### Sau idle timeout

Request:
```http
GET /me
X-Correlation-ID: T9-04-4d1e9d09
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=AKnXZs...r-Vg (sha256:d886262350adad50)
```

Response:
```http
HTTP 401
Set-Cookie: __Host-sid=""; expires=Wed, 28 Oct 2026 03:21:04 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure

{
  "error": "NOT_AUTHENTICATED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:04.440+00:00", "action": "SESSION_CHECK", "result": "DENIED", "actor_id": null, "role": null, "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T9-04-4d1e9d09", "session_id_hash": "d886262350adad50", "details": {"reason": "invalid_or_revoked"}}
```


## b. Absolute timeout 8 giờ tính từ lúc qua MFA

### admin01: bước 1 - password

Request:
```http
POST /auth/login
X-Correlation-ID: T9-05-111acd2c
User-Agent: attmdt-lab01-tests/1.0

{
  "username": "admin01",
  "password": "***(ẩn)"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=v60rpx...CRQQ (sha256:1fa4eb4fb51c0455); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa_required": true
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:04.476+00:00", "action": "LOGIN_PASSWORD", "result": "SUCCESS", "actor_id": 4, "role": "ADMIN", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T9-05-111acd2c", "session_id_hash": "1fa4eb4fb51c0455", "details": {"previous_session_id_hash": null}}
```

### admin01: bước 2 - TOTP

Request:
```http
POST /auth/mfa
X-Correlation-ID: T9-06-20467295
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=v60rpx...CRQQ (sha256:1fa4eb4fb51c0455)

{
  "code": "808377"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=ak5aBB...pQDk (sha256:a66f9dee38d604d2); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa": "verified",
  "username": "admin01",
  "role": "ADMIN"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:30.204+00:00", "action": "MFA_VERIFY", "result": "SUCCESS", "actor_id": 4, "role": "ADMIN", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T9-06-20467295", "session_id_hash": "a66f9dee38d604d2", "details": {"time_step": 59771923, "previous_session_id_hash": "1fa4eb4fb51c0455"}}
```

Giả lập phiên đã sống quá 8 giờ: đặt `auth_at` của session về 8 giờ 1 giây trước.

### Sau absolute timeout

Request:
```http
GET /me
X-Correlation-ID: T9-07-50cb1bc7
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=ak5aBB...pQDk (sha256:a66f9dee38d604d2)
```

Response:
```http
HTTP 401
Set-Cookie: __Host-sid=""; expires=Wed, 28 Oct 2026 03:21:30 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure

{
  "error": "SESSION_EXPIRED"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:21:30.207+00:00", "action": "SESSION_EXPIRED", "result": "DENIED", "actor_id": 4, "role": "ADMIN", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T9-07-50cb1bc7", "session_id_hash": "a66f9dee38d604d2", "details": {"reason": "absolute_timeout_8h"}}
```

