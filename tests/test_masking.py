"""Unit test bộ lọc che dữ liệu của audit log."""

from lab01.audit import mask_pan, scrub


def test_mask_pan_keeps_last4() -> None:
    assert mask_pan("4111111111111111") == "************1111"
    assert mask_pan("thẻ 4111 1111 1111 1111 nhé") == "thẻ ************1111 nhé"
    assert mask_pan("4111-1111-1111-1111") == "************1111"


def test_short_numbers_untouched() -> None:
    text = "đơn ORD-123456, số tiền 250000, mã 737"
    assert mask_pan(text) == text


def test_scrub_redacts_sensitive_keys_recursively() -> None:
    record = {
        "password": "p",
        "details": {"cvv": "737", "totp_secret": "ABC", "note": "4111111111111111"},
        "items": [{"token": "t"}],
    }
    assert scrub(record) == {
        "password": "[REDACTED]",
        "details": {"cvv": "[REDACTED]", "totp_secret": "[REDACTED]", "note": "************1111"},
        "items": [{"token": "[REDACTED]"}],
    }
