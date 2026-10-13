"""Generate SYNTHETIC logs with embedded attack scenarios. No real data is used.

Source IPs come from the RFC 5737 documentation ranges (203.0.113.0/24, 198.51.100.0/24).
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)
OUT = Path(__file__).resolve().parent.parent / "data"
START = datetime(2026, 10, 11, 0, 0, 0)
USERS = ["alice", "bob", "carol", "dave", "erin", "deploy", "backup"]
BENIGN_IPS = [f"198.51.100.{i}" for i in range(10, 25)]


def auth_line(ts, user, ip, ok, invalid=False):
    pid = random.randint(1000, 30000)
    port = random.randint(30000, 65000)
    if ok:
        return f"{ts:%b %e %H:%M:%S} web01 sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"
    inv = "invalid user " if invalid else ""
    return f"{ts:%b %e %H:%M:%S} web01 sshd[{pid}]: Failed password for {inv}{user} from {ip} port {port} ssh2"


def web_line(ts, ip, path, status, ua, method="GET"):
    return f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} {random.randint(200, 9000)} "-" "{ua}"'


def gen_auth():
    rows = []
    for _ in range(300):  # benign logins and the occasional typo
        ts = START + timedelta(seconds=random.randint(0, 86000))
        rows.append((ts, auth_line(ts, random.choice(USERS), random.choice(BENIGN_IPS), random.random() > 0.08)))
    t = START + timedelta(hours=3)  # brute force on root
    for i in range(60):
        ts = t + timedelta(seconds=i * 3)
        rows.append((ts, auth_line(ts, "root", "203.0.113.50", False)))
    t = START + timedelta(hours=9)  # password spraying across accounts
    for i, u in enumerate(USERS + ["admin", "test", "oracle"]):
        ts = t + timedelta(minutes=i * 2)
        rows.append((ts, auth_line(ts, u, "203.0.113.77", False, invalid=u in ("admin", "test", "oracle"))))
    t = START + timedelta(hours=14)  # failures followed by success
    for i in range(8):
        ts = t + timedelta(seconds=i * 20)
        rows.append((ts, auth_line(ts, "deploy", "203.0.113.99", False)))
    ts = t + timedelta(seconds=200)
    rows.append((ts, auth_line(ts, "deploy", "203.0.113.99", True)))
    return [r for _, r in sorted(rows)]


def gen_web():
    rows = []
    uas = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0)", "curl/8.4.0"]
    for _ in range(400):
        ts = START + timedelta(seconds=random.randint(0, 86000))
        path = random.choice(["/", "/index.html", "/about", "/products", "/api/items", "/contact"])
        rows.append((ts, web_line(ts, random.choice(BENIGN_IPS), path, 200, random.choice(uas))))
    t = START + timedelta(hours=5)  # directory and file scanning
    probes = ["/.env", "/wp-login.php", "/phpmyadmin/", "/admin", "/.git/config", "/backup.zip", "/server-status"]
    for i in range(40):
        ts = t + timedelta(seconds=i * 4)
        path = probes[i] if i < len(probes) else f"/hidden{i}"
        rows.append((ts, web_line(ts, "203.0.113.120", path, 404, "Mozilla/5.0 (X11; Linux x86_64)")))
    t = START + timedelta(hours=11)  # SQL injection with a scanner tool
    for i, p in enumerate(["/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
                           "/products?id=1'%20OR%201=1--", "/api/items?id=1%20AND%20SLEEP(5)"]):
        ts = t + timedelta(seconds=i * 7)
        rows.append((ts, web_line(ts, "203.0.113.140", p, 500, "sqlmap/1.7.2#stable")))
    return [r for _, r in sorted(rows)]


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    (OUT / "auth.log").write_text("\n".join(gen_auth()) + "\n")
    (OUT / "access.log").write_text("\n".join(gen_web()) + "\n")
    print("wrote", OUT / "auth.log", "and", OUT / "access.log")
