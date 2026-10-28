"""RBAC: quyền gắn với role, backend kiểm tra ở từng API (không dựa vào việc ẩn nút trên UI).

Separation of Duties: role tạo yêu cầu hoàn tiền (CSKH) và role duyệt chi (KE_TOAN)
không có quyền của nhau; Admin quản trị hệ thống, không tạo hay duyệt tiền.
"""

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "CSKH": frozenset({"refund:create", "refund:read"}),
    "KE_TOAN": frozenset({"refund:approve", "refund:read"}),
    "ADMIN": frozenset({"refund:read"}),
}


def has_permission(role: str, permission: str) -> bool:
    """Role có quyền permission hay không; role lạ không có quyền nào."""
    return permission in ROLE_PERMISSIONS.get(role, frozenset())
