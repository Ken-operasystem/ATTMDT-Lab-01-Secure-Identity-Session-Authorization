# T6 - Luồng hợp lệ

**PASS khi:** CSKH tạo và Kế toán approve thành công đúng role; 2 audit events

**Kết quả:** PASS


## 1. CSKH tạo yêu cầu hoàn tiền

### cskh01: tạo refund

Request:
```http
POST /refunds
X-Correlation-ID: T6-01-115f2b08
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=4gQmtb...TZGQ (sha256:e6c214607b4707c7)

{
  "order_id": "ORD-T6-001",
  "amount": 320000,
  "reason": "Giao sai mẫu"
}
```

Response:
```http
HTTP 201

{
  "id": 2,
  "order_id": "ORD-T6-001",
  "amount": 320000,
  "reason": "Giao sai mẫu",
  "card": null,
  "status": "PENDING",
  "created_by": 1,
  "approved_by": null,
  "created_at": "2026-10-28T03:20:45+00:00",
  "approved_at": null
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.415+00:00", "action": "REFUND_CREATE", "result": "SUCCESS", "actor_id": 1, "role": "CSKH", "object_id": "refund:2", "source_ip": "172.29.0.4", "correlation_id": "T6-01-115f2b08", "session_id_hash": "e6c214607b4707c7", "details": {"order_id": "ORD-T6-001", "amount": 320000, "card_last4": null, "reason": "Giao sai mẫu"}}
```


## 2. Kế toán đăng nhập và duyệt

### ketoan01: bước 1 - password

Request:
```http
POST /auth/login
X-Correlation-ID: T6-02-6b62bd02
User-Agent: attmdt-lab01-tests/1.0

{
  "username": "ketoan01",
  "password": "***(ẩn)"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=upYRKi..._1CI (sha256:939d7f90ba0a3e5d); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa_required": true
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.456+00:00", "action": "LOGIN_PASSWORD", "result": "SUCCESS", "actor_id": 3, "role": "KE_TOAN", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T6-02-6b62bd02", "session_id_hash": "939d7f90ba0a3e5d", "details": {"previous_session_id_hash": null}}
```

### ketoan01: bước 2 - TOTP

Request:
```http
POST /auth/mfa
X-Correlation-ID: T6-03-60ceca5f
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=upYRKi..._1CI (sha256:939d7f90ba0a3e5d)

{
  "code": "678951"
}
```

Response:
```http
HTTP 200
Set-Cookie: __Host-sid=Dpsaav...P3l4 (sha256:c3babf6f0dcdff2f); HttpOnly; Path=/; SameSite=strict; Secure

{
  "mfa": "verified",
  "username": "ketoan01",
  "role": "KE_TOAN"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.461+00:00", "action": "MFA_VERIFY", "result": "SUCCESS", "actor_id": 3, "role": "KE_TOAN", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T6-03-60ceca5f", "session_id_hash": "c3babf6f0dcdff2f", "details": {"time_step": 59771921, "previous_session_id_hash": "939d7f90ba0a3e5d"}}
```

### ketoan01: approve refund

Request:
```http
POST /refunds/2/approve
X-Correlation-ID: T6-04-f33687c0
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=Dpsaav...P3l4 (sha256:c3babf6f0dcdff2f)
```

Response:
```http
HTTP 200

{
  "id": 2,
  "order_id": "ORD-T6-001",
  "amount": 320000,
  "reason": "Giao sai mẫu",
  "card": null,
  "status": "APPROVED",
  "created_by": 1,
  "approved_by": 3,
  "created_at": "2026-10-28T03:20:45+00:00",
  "approved_at": "2026-10-28T03:20:45+00:00"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.469+00:00", "action": "REFUND_APPROVE", "result": "SUCCESS", "actor_id": 3, "role": "KE_TOAN", "object_id": "refund:2", "source_ip": "172.29.0.4", "correlation_id": "T6-04-f33687c0", "session_id_hash": "c3babf6f0dcdff2f", "details": {"amount": 320000}}
```


## 3. Kiểm tra thêm: không duyệt lại được, Kế toán không tạo được refund

### ketoan01: approve lần 2

Request:
```http
POST /refunds/2/approve
X-Correlation-ID: T6-05-da2f5173
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=Dpsaav...P3l4 (sha256:c3babf6f0dcdff2f)
```

Response:
```http
HTTP 409

{
  "error": "INVALID_STATE"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.473+00:00", "action": "REFUND_APPROVE", "result": "FAILURE", "actor_id": 3, "role": "KE_TOAN", "object_id": "refund:2", "source_ip": "172.29.0.4", "correlation_id": "T6-05-da2f5173", "session_id_hash": "c3babf6f0dcdff2f", "details": {"reason": "not_pending"}}
```

### ketoan01: thử tạo refund

Request:
```http
POST /refunds
X-Correlation-ID: T6-06-aa9f9940
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=Dpsaav...P3l4 (sha256:c3babf6f0dcdff2f)

{
  "order_id": "ORD-T6-002",
  "amount": 1000,
  "reason": "SoD"
}
```

Response:
```http
HTTP 403

{
  "error": "FORBIDDEN"
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.476+00:00", "action": "REFUND_CREATE", "result": "DENIED", "actor_id": 3, "role": "KE_TOAN", "object_id": null, "source_ip": "172.29.0.4", "correlation_id": "T6-06-aa9f9940", "session_id_hash": "c3babf6f0dcdff2f", "details": {"reason": "missing_permission", "permission": "refund:create"}}
```

