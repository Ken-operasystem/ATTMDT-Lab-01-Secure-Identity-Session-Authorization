# T7 - Log masking

**PASS khi:** Log không có CVV hay full PAN; PAN chỉ còn last-4

**Kết quả:** PASS


## Gửi PAN và CVV vào luồng tạo refund

Dữ liệu test: PAN `4111 1111 1111 1111` (thẻ test Visa), CVV `737`; PAN được gửi ở cả trường card_pan và trong lý do (văn bản tự do).

### cskh01: tạo refund có PAN/CVV

Request:
```http
POST /refunds
X-Correlation-ID: T7-01-8bb43314
User-Agent: attmdt-lab01-tests/1.0
Cookie: __Host-sid=4gQmtb...TZGQ (sha256:e6c214607b4707c7)

{
  "order_id": "ORD-T7-001",
  "amount": 250000,
  "reason": "Hoàn về thẻ 4111 1111 1111 1111 theo yêu cầu khách",
  "card_pan": "4111 1111 1111 1111",
  "cvv": "737"
}
```

Response:
```http
HTTP 201

{
  "id": 3,
  "order_id": "ORD-T7-001",
  "amount": 250000,
  "reason": "Hoàn về thẻ ************1111 theo yêu cầu khách",
  "card": "**** **** **** 1111",
  "status": "PENDING",
  "created_by": 1,
  "approved_by": null,
  "created_at": "2026-10-28T03:20:45+00:00",
  "approved_at": null
}
```

Audit log (cùng X-Correlation-ID):
```json
{"timestamp": "2026-10-28T03:20:45.490+00:00", "action": "REFUND_CREATE", "result": "SUCCESS", "actor_id": 1, "role": "CSKH", "object_id": "refund:3", "source_ip": "172.29.0.4", "correlation_id": "T7-01-8bb43314", "session_id_hash": "e6c214607b4707c7", "details": {"order_id": "ORD-T7-001", "amount": 250000, "card_last4": "1111", "reason": "Hoàn về thẻ ************1111 theo yêu cầu khách"}}
```


## Kết luận

Audit log ở trên: card_last4 = 1111, PAN trong lý do bị che còn `************1111`, không có trường cvv. API trả về và DB chỉ giữ 4 số cuối (cột pan_last4).

