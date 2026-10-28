# T5 - RBAC bypass

**PASS khi:** 403; audit result=DENIED

**Kết quả:** PASS


## CSKH tạo yêu cầu hoàn tiền (hợp lệ)

### cskh01: tạo refund

Request:
```http
POST /refunds
X-Correlation-ID: T5-01-52a138eb
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=4gQmtb...TZGQ (sha256:e6c214607b4707c7)

{
  "order_id": "ORD-T5-001",
  "amount": 150000,
  "reason": "Khách trả hàng"
}
```

Response:
```http
HTTP 201

{
  "id": 1,
  "order_id": "ORD-T5-001",
  "amount": 150000,
  "reason": "Khách trả hàng",
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
{"timestamp": "2026-10-28T03:20:45.394+00:00", "action": "REFUND_CREATE", "result": "SUCCESS", "actor_id": 1, "role": "CSKH", "object_id": "refund:1", "source_ip": "172.29.0.4", "correlation_id": "T5-01-52a138eb", "session_id_hash": "e6c214607b4707c7", "details": {"order_id": "ORD-T5-001", "amount": 150000, "card_last4": null, "reason": "Khách trả hàng"}}
```


## CSKH gọi thẳng API approve (không qua UI)

### cskh01: approve refund

Request:
```http
POST /refunds/1/approve
X-Correlation-ID: T5-02-29ef37ed
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=4gQmtb...TZGQ (sha256:e6c214607b4707c7)
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
{"timestamp": "2026-10-28T03:20:45.397+00:00", "action": "REFUND_APPROVE", "result": "DENIED", "actor_id": 1, "role": "CSKH", "object_id": "refund:1", "source_ip": "172.29.0.4", "correlation_id": "T5-02-29ef37ed", "session_id_hash": "e6c214607b4707c7", "details": {"reason": "missing_permission", "permission": "refund:approve"}}
```

### Refund vẫn PENDING

Request:
```http
GET /refunds/1
X-Correlation-ID: T5-03-91e96872
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=4gQmtb...TZGQ (sha256:e6c214607b4707c7)
```

Response:
```http
HTTP 200

{
  "id": 1,
  "order_id": "ORD-T5-001",
  "amount": 150000,
  "reason": "Khách trả hàng",
  "card": null,
  "status": "PENDING",
  "created_by": 1,
  "approved_by": null,
  "created_at": "2026-10-28T03:20:45+00:00",
  "approved_at": null
}
```

