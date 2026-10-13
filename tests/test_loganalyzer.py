import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

from loganalyzer import detections as d
from loganalyzer.models import AuthEvent, WebEvent
from loganalyzer.parsers import parse_auth_line, parse_web_line

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 10, 11, 3, 0, 0)


def fail(ip, user, sec):
    return AuthEvent(T0 + timedelta(seconds=sec), ip, user, False)


def ok(ip, user, sec):
    return AuthEvent(T0 + timedelta(seconds=sec), ip, user, True)


def web(ip, path, status, ua="Mozilla/5.0", sec=0):
    return WebEvent(T0 + timedelta(seconds=sec), ip, "GET", path, status, ua)


def test_parse_failed_invalid_user():
    line = "Oct 11 03:14:07 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52114 ssh2"
    ev = parse_auth_line(line, 2026)
    assert (ev.user, ev.ip, ev.success, ev.invalid_user) == ("admin", "203.0.113.5", False, True)


def test_parse_accepted():
    line = "Oct  1 23:59:59 web01 sshd[9]: Accepted password for alice from 198.51.100.7 port 4000 ssh2"
    ev = parse_auth_line(line, 2026)
    assert ev.success and ev.user == "alice" and ev.ts.day == 1


def test_parse_web_line():
    line = '203.0.113.9 - - [11/Oct/2026:03:15:01 +0000] "GET /wp-login.php HTTP/1.1" 404 512 "-" "sqlmap/1.7"'
    ev = parse_web_line(line)
    assert (ev.ip, ev.path, ev.status) == ("203.0.113.9", "/wp-login.php", 404) and "sqlmap" in ev.user_agent


def test_unparseable_lines_return_none():
    assert parse_auth_line("garbage", 2026) is None
    assert parse_web_line("garbage") is None


def test_brute_force_detected_and_threshold_respected():
    events = [fail("1.1.1.1", "root", i * 2) for i in range(12)]
    assert len(d.brute_force(events, threshold=10)) == 1
    assert d.brute_force(events[:5], threshold=10) == []


def test_brute_force_requires_window():
    spread = [fail("1.1.1.1", "root", i * 3600) for i in range(12)]  # one per hour
    assert d.brute_force(spread, threshold=10, window_min=5) == []


def test_password_spraying_counts_distinct_users():
    events = [fail("2.2.2.2", f"user{i}", i * 30) for i in range(6)]
    alerts = d.password_spraying(events, min_users=5)
    assert len(alerts) == 1 and alerts[0].mitre == "T1110.003"
    same_user = [fail("2.2.2.2", "root", i * 30) for i in range(6)]
    assert d.password_spraying(same_user, min_users=5) == []


def test_success_after_failures():
    events = [fail("3.3.3.3", "deploy", i * 10) for i in range(6)] + [ok("3.3.3.3", "deploy", 100)]
    alerts = d.success_after_failures(events, min_failures=5)
    assert len(alerts) == 1 and alerts[0].rule == "success_after_failures"
    assert d.success_after_failures([ok("3.3.3.3", "deploy", 0)]) == []


def test_web_scanning_via_404s():
    events = [web("4.4.4.4", f"/x{i}", 404, sec=i) for i in range(20)]
    assert len(d.web_scanning(events, min_404=15)) == 1


def test_web_scanning_via_sensitive_paths():
    events = [web("5.5.5.5", p, 200, sec=i) for i, p in enumerate(["/.env", "/wp-login.php", "/admin"])]
    assert len(d.web_scanning(events)) == 1


def test_scanner_user_agent_and_sqli():
    events = [web("6.6.6.6", "/p?id=1%20UNION%20SELECT%20a", 500, ua="sqlmap/1.7")]
    assert len(d.scanner_user_agent(events)) == 1
    assert len(d.sql_injection_attempts(events)) == 1
    assert d.sql_injection_attempts([web("7.7.7.7", "/products?id=3", 200)]) == []


def test_benign_traffic_produces_no_alerts():
    auth = [ok("198.51.100.10", "alice", i * 600) for i in range(5)] + [fail("198.51.100.10", "alice", 10)]
    webs = [web("198.51.100.10", "/", 200, sec=i) for i in range(10)]
    assert d.run_all(auth, webs) == []


def test_end_to_end_on_generated_logs(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "scripts" / "generate_sample_logs.py")], check=True)
    out = tmp_path / "report.json"
    subprocess.run([sys.executable, "-m", "loganalyzer", "--auth", str(ROOT / "data/auth.log"),
                    "--web", str(ROOT / "data/access.log"), "--format", "json", "--out", str(out)],
                   check=True, cwd=ROOT)
    import json
    alerts = json.loads(out.read_text())
    found = {(a["rule"], a["ip"]) for a in alerts}
    assert ("ssh_brute_force", "203.0.113.50") in found
    assert ("password_spraying", "203.0.113.77") in found
    assert ("success_after_failures", "203.0.113.99") in found
    assert ("web_scanning", "203.0.113.120") in found
    assert ("sql_injection_attempt", "203.0.113.140") in found
    assert not any(a["ip"].startswith("198.51.100.") for a in alerts)  # benign IPs stay clean
