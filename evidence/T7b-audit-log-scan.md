# T7b - Quét toàn bộ audit log sau T1-T9

**PASS khi:** Không có password, TOTP secret, raw session ID, full PAN hay CVV trong log

**Kết quả:** PASS


## Kết quả quét audit.log (41 dòng)

| Loại dữ liệu | Số giá trị kiểm | Số lần xuất hiện trong log |
|---|---|---|
| Mật khẩu (seed + mật khẩu mới đổi ở T8) | 4 | 0 |
| TOTP secret (seed + secret mới ở T8) | 4 | 0 |
| Session ID đầy đủ đã cấp trong T1-T9 | 17 | 0 |
| Full PAN | 2 | 0 |
| Trường cvv | 1 | 0 |

Toàn bộ audit log của lần chạy này: [audit-full.log](audit-full.log).

