# ATTMDT Lab 01 - Secure Identity, Session & Authorization

Cổng quản trị sàn TMĐT cho CSKH, Kế toán và Admin, tập trung vào luồng hoàn tiền. Lab bổ sung các control còn thiếu: đăng nhập 2 bước TOTP, chống replay OTP, bảo vệ session, RBAC + Separation of Duties, audit log có che dữ liệu, và thu hồi session. Mỗi control có code, test chủ động và evidence.

Các quyết định bảo mật: [SECURITY_DECISIONS.md](SECURITY_DECISIONS.md). Kết quả test: [evidence/SUMMARY.md](evidence/SUMMARY.md).

## Kiến trúc

| Thành phần | Vai trò |
|---|---|
| `app` (FastAPI, Python 3.12) | API, chỉ mở `127.0.0.1:8000` trên máy chạy |
| `redis` (Redis 7.4) | Session phía server và key chống replay OTP; không publish port, bắt buộc mật khẩu, `noeviction` |
| SQLite (`/data/lab01.db` trong container) | Bảng `users`, `refunds`; tạo lại và seed user demo mỗi lần container khởi động |
| Audit log | JSON lines ghi vào volume `audit-logs` (`/app/logs/audit.log`) và stdout |

```text
.
├── app/lab01/          # mã nguồn
│   ├── main.py         # API: đăng nhập, session, hoàn tiền
│   ├── totp.py         # TOTP RFC 6238
│   ├── sessions.py     # session trong Redis, xoay và thu hồi
│   ├── rbac.py         # role -> quyền
│   ├── audit.py        # audit log + che dữ liệu
│   ├── passwords.py    # băm mật khẩu scrypt
│   └── db.py           # SQLite, seed user demo
├── tests/              # test chủ động T1-T9 + unit test TOTP/masking
├── redis/redis.conf    # cấu hình Redis
├── docker-compose.yml  # redis + app + tests
├── Dockerfile
├── scripts/            # tạo .env, chạy test, quét bí mật
└── evidence/           # kết quả lần chạy test gần nhất
```

## Chạy

Cần Docker kèm Docker Compose v2 và Python 3 (chỉ để chạy 2 script nhỏ trong `scripts/`).

```bash
python3 scripts/gen_env.py     # tạo .env: mật khẩu Redis, mật khẩu + TOTP secret ngẫu nhiên cho user demo
./scripts/run-tests.sh         # dựng redis + app sạch, chạy toàn bộ test, ghi evidence/
```

`run-tests.sh` xóa container và volume cũ, build image, chờ Redis và app healthy, chạy pytest trong container `tests`, rồi quét evidence để chắc không có giá trị nào trong `.env` bị lộ. Kết quả:

- `evidence/SUMMARY.md`: bảng PASS/FAIL của từng test.
- `evidence/Tn-*.md`: request, response, Set-Cookie, key Redis và audit log của từng bước.
- `evidence/audit-full.log`: toàn bộ audit log của lần chạy; `evidence/app-stdout.log`: stdout của app.
- `evidence/pytest-output.txt`, `evidence/secret-scan.txt`.

Chỉ chạy app: `docker compose up -d --build --wait redis app`. Dừng và xóa: `docker compose down -v`.

## Thử bằng curl

Mật khẩu lấy từ `.env`. Mã TOTP lấy bằng lệnh trong container app, đóng vai app Authenticator.

```bash
set -a; . ./.env; set +a
printf '{"username":"cskh01","password":"%s"}' "$SEED_PASSWORD_CSKH01" \
  | curl -s -c jar -b jar -H 'Content-Type: application/json' --data @- http://localhost:8000/auth/login
CODE=$(docker compose exec -T app python -m lab01.totp cskh01)
printf '{"code":"%s"}' "$CODE" \
  | curl -s -c jar -b jar -H 'Content-Type: application/json' --data @- http://localhost:8000/auth/mfa
curl -s -b jar http://localhost:8000/me
curl -s -b jar -X POST http://localhost:8000/refunds/1/approve    # CSKH -> 403 FORBIDDEN
```

Mật khẩu đi vào curl qua stdin (`--data @-`) để không nằm trên dòng lệnh. Cookie có cờ `Secure`; curl và trình duyệt vẫn gửi cookie này tới `localhost` qua HTTP.

## User demo và quyền

| User | Role | Quyền |
|---|---|---|
| cskh01, cskh02 | CSKH | `refund:create`, `refund:read` |
| ketoan01 | KE_TOAN | `refund:approve`, `refund:read` |
| admin01 | ADMIN | `refund:read` |

## API

| Method | Path | Ghi chú |
|---|---|---|
| GET | `/auth/session` | Trạng thái phiên; chưa có thì cấp phiên ẩn danh |
| POST | `/auth/login` | Bước 1: username + password, trả SID mới ở trạng thái chờ MFA |
| POST | `/auth/mfa` | Bước 2: mã TOTP 6 số, chống replay, xoay SID |
| GET | `/me` | Thông tin phiên đã xác thực |
| POST | `/auth/logout` | Hủy phiên hiện tại |
| POST | `/auth/password` | Đổi mật khẩu, hủy mọi phiên của user |
| POST | `/auth/mfa/reset` | Cấp TOTP secret mới, hủy mọi phiên của user |
| POST | `/refunds` | Tạo yêu cầu hoàn tiền (CSKH) |
| GET | `/refunds`, `/refunds/{id}` | Xem yêu cầu |
| POST | `/refunds/{id}/approve` | Duyệt chi (Kế toán, khác người tạo, chỉ khi PENDING) |

Lỗi trả dạng `{"error": "CODE"}`. Mỗi response có header `X-Correlation-ID`, trùng với `correlation_id` trong audit log.

## Kỹ thuật, code và test

| Kỹ thuật | Code | Test |
|---|---|---|
| 1. TOTP RFC 6238 | `totp.py`, `main.py: verify_mfa` | T1, T3, `test_totp_rfc6238.py` (vector RFC 6238 Appendix B) |
| 2. Anti-replay bằng Redis | `main.py: verify_mfa` (`SET NX EX`), `config.py: replay_ttl` | T2 |
| 3. Session hardening | `sessions.py`, `main.py: current_session`, `_set_session_cookie` | T4, T9 |
| 4. RBAC + SoD | `rbac.py`, `main.py: require`, `approve_refund`, CHECK trong `db.py` | T5, T6 |
| 5. Audit và data masking | `audit.py`, `main.py: _audit`, `create_refund` | T7, T7b, `test_masking.py` |
| 6. Revocation | `sessions.py: revoke_all`, `main.py: logout`, `change_password`, `reset_mfa`, `current_session` | T8 |
