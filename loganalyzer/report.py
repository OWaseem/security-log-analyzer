import json
from collections import Counter
from typing import List

from .models import Alert


def to_markdown(alerts: List[Alert], auth_count: int, web_count: int) -> str:
    sev = Counter(a.severity for a in alerts)
    lines = [
        "# Security Log Analysis Report", "",
        f"- Auth events parsed: **{auth_count}**",
        f"- Web events parsed: **{web_count}**",
        f"- Alerts: **{len(alerts)}** (high: {sev['high']}, medium: {sev['medium']}, low: {sev['low']})", "",
    ]
    if not alerts:
        lines.append("No alerts triggered.")
        return "\n".join(lines) + "\n"
    lines += ["| Severity | Rule | Source IP | Count | MITRE | First seen | Detail |",
              "|---|---|---|---|---|---|---|"]
    for a in alerts:
        lines.append(f"| {a.severity} | {a.rule} | {a.ip} | {a.count} | {a.mitre} | {a.first_seen:%Y-%m-%d %H:%M} | {a.detail} |")
    ips = Counter(a.ip for a in alerts).most_common(5)
    lines += ["", "## Top offending IPs", ""] + [f"- {ip}: {n} alert(s)" for ip, n in ips]
    return "\n".join(lines) + "\n"


def to_json(alerts: List[Alert]) -> str:
    return json.dumps([a.to_dict() for a in alerts], indent=2)
