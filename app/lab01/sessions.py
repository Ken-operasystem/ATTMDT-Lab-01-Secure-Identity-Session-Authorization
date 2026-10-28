"""Session phía server trong Redis; cookie chỉ mang Session ID ngẫu nhiên.

Redis chỉ lưu SHA-256 của Session ID (key sess:<hash>), nên đọc được Redis
cũng không lấy được cookie hợp lệ. Mỗi user có tập user_sess:<id> để thu hồi
toàn bộ phiên khi đổi mật khẩu hoặc reset MFA.
"""

import hashlib
import secrets
import time

import redis

ANONYMOUS = "anonymous"
PENDING_MFA = "pending_mfa"
AUTHENTICATED = "authenticated"


def sid_hash(sid: str) -> str:
    """SHA-256 của Session ID."""
    return hashlib.sha256(sid.encode()).hexdigest()


def ua_hash(user_agent: str) -> str:
    """Dấu vân tay User-Agent để phát hiện session bị dùng từ client khác."""
    return hashlib.sha256(user_agent.encode()).hexdigest()[:32]


class SessionStore:
    """Tạo, đọc, gia hạn và thu hồi session."""

    def __init__(self, client: redis.Redis, ttl_by_state: dict[str, int], index_ttl: int) -> None:
        self.redis = client
        self.ttl_by_state = ttl_by_state
        self.index_ttl = index_ttl

    @staticmethod
    def _key(hashed: str) -> str:
        return f"sess:{hashed}"

    @staticmethod
    def _index(user_id: int | str) -> str:
        return f"user_sess:{user_id}"

    def create(
        self,
        state: str,
        user_agent: str,
        user_id: int | None = None,
        username: str | None = None,
        role: str | None = None,
    ) -> str:
        """Sinh Session ID mới (256 bit) và lưu trạng thái phiên; trả về Session ID."""
        sid = secrets.token_urlsafe(32)
        hashed = sid_hash(sid)
        now = str(time.time())
        data = {"state": state, "created_at": now, "ua_hash": ua_hash(user_agent)}
        if user_id is not None:
            data.update(user_id=str(user_id), username=username or "", role=role or "")
        if state == AUTHENTICATED:
            data["auth_at"] = now
        pipe = self.redis.pipeline(transaction=True)
        pipe.hset(self._key(hashed), mapping=data)
        pipe.expire(self._key(hashed), self.ttl_by_state[state])
        if user_id is not None:
            pipe.sadd(self._index(user_id), hashed)
            pipe.expire(self._index(user_id), self.index_ttl)
        pipe.execute()
        return sid

    def load(self, sid: str | None) -> dict[str, str] | None:
        """Đọc session theo Session ID trong cookie; None nếu không có hoặc đã hết hạn."""
        if not sid or len(sid) > 128:
            return None
        hashed = sid_hash(sid)
        data = self.redis.hgetall(self._key(hashed))
        if not data:
            return None
        data["sid_hash"] = hashed
        return data

    def touch(self, session: dict[str, str]) -> None:
        """Gia hạn idle timeout sau mỗi request hợp lệ."""
        self.redis.expire(self._key(session["sid_hash"]), self.ttl_by_state[session["state"]])

    def destroy(self, session: dict[str, str]) -> None:
        """Hủy một session."""
        pipe = self.redis.pipeline(transaction=True)
        pipe.delete(self._key(session["sid_hash"]))
        if session.get("user_id"):
            pipe.srem(self._index(session["user_id"]), session["sid_hash"])
        pipe.execute()

    def revoke_all(self, user_id: int) -> int:
        """Hủy mọi session của user; trả về số session còn sống đã bị hủy."""
        members = self.redis.smembers(self._index(user_id))
        pipe = self.redis.pipeline(transaction=True)
        for hashed in members:
            pipe.delete(self._key(hashed))
        pipe.delete(self._index(user_id))
        results = pipe.execute()
        return sum(results[: len(members)])
