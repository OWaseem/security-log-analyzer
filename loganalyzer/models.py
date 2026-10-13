from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class AuthEvent:
    ts: datetime
    ip: str
    user: str
    success: bool
    invalid_user: bool = False


@dataclass(frozen=True)
class WebEvent:
    ts: datetime
    ip: str
    method: str
    path: str
    status: int
    user_agent: str


@dataclass
class Alert:
    rule: str
    severity: str  # low | medium | high
    ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    mitre: str
    detail: str = ""
    users: list = field(default_factory=list)

    def to_dict(self):
        return {
            "rule": self.rule,
            "severity": self.severity,
            "ip": self.ip,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "mitre": self.mitre,
            "detail": self.detail,
            "users": self.users,
        }
