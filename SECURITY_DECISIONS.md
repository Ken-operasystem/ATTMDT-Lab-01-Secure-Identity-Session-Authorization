# Các quyết định bảo mật

## 1. TOTP RFC 6238

- HOTP-SHA1, 6 chữ số, time-step 30 giây, T0 = 0, tự cài theo RFC (không phụ thuộc thư viện) để biết chính xác time-step nào khớp; kiểm bằng vector RFC 6238 Appendix B.
- Cửa sổ chấp nhận ±1 step cho lệch giờ; so sánh mã bằng `hmac.compare_digest`; chỉ nhận đúng 6 chữ số ASCII.
- TOTP secret không bao giờ được ghi log: audit chỉ ghi `time_step`, và bộ lọc log xóa mọi trường tên `secret`, `totp_secret`, `code`, `otp`.
- Sai mã 5 lần trong 5 phút (tính cả replay) thì khóa bước MFA (429) và hủy phiên chờ MFA, để không dò được 10^6 mã.

## 2. Chống replay bằng Redis

- Sau khi mã đúng, ghi `SET totp:used:<user_id>:<time_step> 1 NX EX 120`. Lệnh trả về rỗng nghĩa là step này đã dùng, trả `REPLAY_DETECTED` dù mã vẫn còn trong cửa sổ.
- TTL 120 giây: mã của step s còn được nhận khi step hiện tại nằm trong [s-1, s+1], tức tối đa 90 giây kể từ lúc key được ghi, cộng 30 giây dự phòng.
- Kiểm mã trước rồi mới ghi key, nên mã sai không tạo key. `SET NX` là một lệnh nguyên tử, hai request đồng thời cùng mã chỉ một request thắng.
- Redis đặt `maxmemory-policy noeviction`: đầy bộ nhớ thì lỗi ghi, không xóa ngầm key replay.

## 3. Session hardening

- Session lưu phía server trong Redis; cookie chỉ chứa Session ID ngẫu nhiên 256 bit. Redis giữ SHA-256 của SID làm key, nên đọc được Redis cũng không có cookie hợp lệ.
- Cookie `__Host-sid`: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, không `Domain`.
- Xoay SID ở mỗi lần tăng quyền: ẩn danh, sau password (chờ MFA), sau MFA. SID cũ bị xóa khỏi Redis ngay, chống session fixation. Server không nhận SID do client tự đặt.
- Idle timeout 15 phút là TTL của key session, gia hạn sau mỗi request hợp lệ. Absolute timeout 8 giờ tính từ lúc qua MFA (`auth_at`), kiểm ở mọi request. Phiên chờ MFA sống 5 phút.

## 4. RBAC + Separation of Duties

- Quyền gắn với role (`rbac.py`), kiểm ở backend bằng dependency `require(permission)` trên từng API. Ẩn nút trên UI không có tác dụng bảo vệ.
- CSKH chỉ có `refund:create`, Kế toán chỉ có `refund:approve`, Admin không tạo cũng không duyệt tiền.
- SoD kiểm 3 lớp: role không có quyền của nhau; người duyệt phải khác người tạo; CHECK trong bảng `refunds` chặn `approved_by = created_by`. Duyệt chỉ áp dụng cho yêu cầu đang PENDING, nên không duyệt được 2 lần.
- Role và actor lấy từ session phía server, không lấy từ input của client.

## 5. Audit và data masking

- Mỗi event có `timestamp`, `actor_id`, `role`, `action`, `object_id`, `result`, `source_ip`, `correlation_id`, `session_id_hash` (16 ký tự đầu SHA-256 của SID, không phải SID).
- Che ở 2 lớp. Tại nguồn: DB và log chỉ nhận 4 số cuối của thẻ; CVV không có trong model nên không lưu và không log. Bộ lọc chung: trước khi ghi, mọi trường tên nhạy cảm bị thay bằng `[REDACTED]`, mọi dãy 13-19 chữ số bị che còn 4 số cuối, kể cả số thẻ người dùng gõ vào ô lý do.
- Lỗi validate (422) chỉ trả tên trường, không trả lại giá trị đã gửi.
- `correlation_id` nhận từ header `X-Correlation-ID` nếu hợp lệ, trả lại trong response để nối request với log.

## 6. Revocation

- Logout hủy phiên hiện tại. Đổi mật khẩu và reset MFA hủy mọi phiên của user (bonus) qua tập `user_sess:<user_id>` trong Redis.
- Phát hiện bất thường: phiên bị dùng với User-Agent khác lúc đăng nhập thì hủy ngay và ghi `SESSION_ANOMALY`.
- Request bằng phiên đã hủy nhận 401 và cookie bị xóa.

## Giới hạn đã biết

- Lab chạy HTTP trên localhost; môi trường thật cần TLS ở reverse proxy. Cookie luôn đặt `Secure`.
- TOTP secret lưu dạng rõ trong SQLite; môi trường thật cần mã hóa bằng khóa từ KMS hoặc Vault.
- Bước password chưa có rate limit theo IP hoặc user; hiện mới khóa ở bước MFA.
- So khớp User-Agent là tín hiệu bất thường yếu, kẻ đã có cookie vẫn giả được. Đây chỉ là ví dụ cho nhánh "phát hiện bất thường" của yêu cầu revocation.
