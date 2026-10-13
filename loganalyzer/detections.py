"""Detection rules. Each rule takes parsed events and returns a list of Alerts.

Thresholds are parameters so they can be tuned; defaults are conservative examples.
"""
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Sequence
from urllib.parse import unquote

from .models import Alert, AuthEvent, WebEvent

SCANNER_AGENTS = ("sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "wpscan", "hydra")
SENSITIVE_PATHS = ("/.env", "/.git/config", "/wp-login.php", "/phpmyadmin", "/admin", "/server-status", "/etc/passwd")
SQLI_MARKERS = ("union select", "' or 1=1", "or 1=1--", "sleep(", "information_schema")


def _group_by_ip(events):
    groups: Dict[str, list] = defaultdict(list)
    for e in events:
        groups[e.ip].append(e)
    for ip in groups:
        groups[ip].sort(key=lambda e: e.ts)
    return groups


def _max_window(times, window: timedelta):
    """Return (count, start_idx, end_idx) of the densest sliding window over sorted times."""
    best = (0, 0, 0)
    left = 0
    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        if right - left + 1 > best[0]:
            best = (right - left + 1, left, right)
    return best


def brute_force(events: Sequence[AuthEvent], threshold=10, window_min=5) -> List[Alert]:
    """Many failed logins from one IP in a short window (MITRE T1110)."""
    alerts = []
    fails = [e for e in events if not e.success]
    for ip, evs in _group_by_ip(fails).items():
        times = [e.ts for e in evs]
        count, lo, hi = _max_window(times, timedelta(minutes=window_min))
        if count >= threshold:
            users = sorted({e.user for e in evs[lo:hi + 1]})
            alerts.append(Alert(
                rule="ssh_brute_force", severity="high" if count >= threshold * 3 else "medium",
                ip=ip, count=count, first_seen=times[lo], last_seen=times[hi], mitre="T1110",
                detail=f"{count} failed logins within {window_min} minutes", users=users[:10]))
    return alerts


def password_spraying(events: Sequence[AuthEvent], min_users=5, window_min=30) -> List[Alert]:
    """One IP failing against many distinct accounts (MITRE T1110.003)."""
    alerts = []
    fails = [e for e in events if not e.success]
    for ip, evs in _group_by_ip(fails).items():
        start = 0
        best_users, best = set(), None
        for end in range(len(evs)):
            while evs[end].ts - evs[start].ts > timedelta(minutes=window_min):
                start += 1
            users = {e.user for e in evs[start:end + 1]}
            if len(users) > len(best_users):
                best_users, best = users, (start, end)
        if len(best_users) >= min_users:
            s, e = best
            alerts.append(Alert(
                rule="password_spraying", severity="high", ip=ip, count=len(best_users),
                first_seen=evs[s].ts, last_seen=evs[e].ts, mitre="T1110.003",
                detail=f"{len(best_users)} distinct accounts targeted within {window_min} minutes",
                users=sorted(best_users)[:10]))
    return alerts


def success_after_failures(events: Sequence[AuthEvent], min_failures=5, window_min=15) -> List[Alert]:
    """A successful login right after repeated failures from the same IP (possible compromise, T1078)."""
    alerts = []
    for ip, evs in _group_by_ip(events).items():
        for i, ev in enumerate(evs):
            if not ev.success:
                continue
            recent = [e for e in evs[:i] if not e.success and ev.ts - e.ts <= timedelta(minutes=window_min)]
            if len(recent) >= min_failures:
                alerts.append(Alert(
                    rule="success_after_failures", severity="high", ip=ip, count=len(recent),
                    first_seen=recent[0].ts, last_seen=ev.ts, mitre="T1078",
                    detail=f"login as '{ev.user}' succeeded after {len(recent)} failures", users=[ev.user]))
                break
    return alerts


def web_scanning(events: Sequence[WebEvent], min_404=15, window_min=10) -> List[Alert]:
    """One IP generating many 404s or probing sensitive paths (MITRE T1595.002)."""
    alerts = []
    for ip, evs in _group_by_ip(events).items():
        misses = [e for e in evs if e.status == 404]
        count, lo, hi = _max_window([e.ts for e in misses], timedelta(minutes=window_min)) if misses else (0, 0, 0)
        sensitive = sorted({e.path.split("?")[0] for e in evs if any(e.path.lower().startswith(p) for p in SENSITIVE_PATHS)})
        if count >= min_404 or len(sensitive) >= 3:
            alerts.append(Alert(
                rule="web_scanning", severity="medium", ip=ip, count=max(count, len(sensitive)),
                first_seen=evs[0].ts, last_seen=evs[-1].ts, mitre="T1595.002",
                detail=f"{count} 404s in {window_min} min; sensitive paths probed: {', '.join(sensitive[:5]) or 'none'}"))
    return alerts


def scanner_user_agent(events: Sequence[WebEvent]) -> List[Alert]:
    """Requests from known scanning or attack tools (MITRE T1595)."""
    alerts = []
    for ip, evs in _group_by_ip(events).items():
        hits = [e for e in evs if any(s in e.user_agent.lower() for s in SCANNER_AGENTS)]
        if hits:
            tools = sorted({s for e in hits for s in SCANNER_AGENTS if s in e.user_agent.lower()})
            alerts.append(Alert(
                rule="scanner_user_agent", severity="medium", ip=ip, count=len(hits),
                first_seen=hits[0].ts, last_seen=hits[-1].ts, mitre="T1595",
                detail=f"known tool user agent(s): {', '.join(tools)}"))
    return alerts


def sql_injection_attempts(events: Sequence[WebEvent]) -> List[Alert]:
    """SQL injection patterns in request paths or query strings (MITRE T1190)."""
    alerts = []
    for ip, evs in _group_by_ip(events).items():
        hits = [e for e in evs if any(m in unquote(e.path).lower() for m in SQLI_MARKERS)]
        if hits:
            alerts.append(Alert(
                rule="sql_injection_attempt", severity="high", ip=ip, count=len(hits),
                first_seen=hits[0].ts, last_seen=hits[-1].ts, mitre="T1190",
                detail=f"{len(hits)} requests with SQL injection patterns"))
    return alerts


def run_all(auth: Sequence[AuthEvent], web: Sequence[WebEvent]) -> List[Alert]:
    alerts = []
    alerts += brute_force(auth) + password_spraying(auth) + success_after_failures(auth)
    alerts += web_scanning(web) + scanner_user_agent(web) + sql_injection_attempts(web)
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(alerts, key=lambda a: (order[a.severity], -a.count))
