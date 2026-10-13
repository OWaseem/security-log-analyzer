"""Parsers for OpenSSH syslog lines and Apache/Nginx combined access logs."""
import re
from datetime import datetime
from typing import Iterable, Iterator, Optional

from .models import AuthEvent, WebEvent

_AUTH_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted) \w+ for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

_WEB_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)


def parse_auth_line(line: str, year: int) -> Optional[AuthEvent]:
    m = _AUTH_RE.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    return AuthEvent(
        ts=ts,
        ip=m["ip"],
        user=m["user"],
        success=m["result"] == "Accepted",
        invalid_user=bool(m["invalid"]),
    )


def parse_web_line(line: str) -> Optional[WebEvent]:
    m = _WEB_RE.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    return WebEvent(
        ts=ts,
        ip=m["ip"],
        method=m["method"],
        path=m["path"],
        status=int(m["status"]),
        user_agent=m["ua"],
    )


def parse_auth(lines: Iterable[str], year: int) -> Iterator[AuthEvent]:
    for line in lines:
        ev = parse_auth_line(line, year)
        if ev:
            yield ev


def parse_web(lines: Iterable[str]) -> Iterator[WebEvent]:
    for line in lines:
        ev = parse_web_line(line)
        if ev:
            yield ev
