# Tổng hợp kết quả test

| Test | Nội dung | Kết quả | Evidence |
|---|---|---|---|
| T1 | TOTP hợp lệ | PASS | [T1-totp-valid.md](T1-totp-valid.md) |
| T2 | Replay OTP | PASS | [T2-replay-otp.md](T2-replay-otp.md) |
| T3 | OTP sai / hết hạn | PASS | [T3-wrong-expired-otp.md](T3-wrong-expired-otp.md) |
| T4 | Session Fixation | PASS | [T4-session-fixation.md](T4-session-fixation.md) |
| T5 | RBAC bypass | PASS | [T5-rbac-bypass.md](T5-rbac-bypass.md) |
| T6 | Luồng hợp lệ | PASS | [T6-valid-flow.md](T6-valid-flow.md) |
| T7 | Log masking | PASS | [T7-log-masking.md](T7-log-masking.md) |
| T8 | Session revocation | PASS | [T8-session-revocation.md](T8-session-revocation.md) |
| T9 | Idle 15 phút / absolute 8 giờ (bổ sung kỹ thuật 3) | PASS | [T9-session-timeouts.md](T9-session-timeouts.md) |
| T7b | Quét toàn bộ audit log sau T1-T9 | PASS | [T7b-audit-log-scan.md](T7b-audit-log-scan.md) |
