# Security Log Analyzer

A small Python tool that reads **SSH authentication logs** and **web server access logs**, applies rule-based detections, and writes a triage report with MITRE ATT&CK technique IDs. It uses only the Python standard library.

## Detections

| Rule | What it looks for | MITRE ATT&CK |
|---|---|---|
| `ssh_brute_force` | Many failed logins from one IP inside a sliding time window | T1110 |
| `password_spraying` | One IP failing against many distinct accounts | T1110.003 |
| `success_after_failures` | A successful login right after repeated failures from the same IP | T1078 |
| `web_scanning` | Bursts of 404s or probing of sensitive paths (`/.env`, `/.git/config`, `/phpmyadmin`) | T1595.002 |
| `scanner_user_agent` | Known attack-tool user agents (sqlmap, nikto, nmap, ...) | T1595 |
| `sql_injection_attempt` | SQL injection patterns in URLs (`UNION SELECT`, `OR 1=1`, `SLEEP(`) | T1190 |

Thresholds and window sizes are function parameters in `loganalyzer/detections.py`, so they can be tuned.

## Usage

```bash
python scripts/generate_sample_logs.py          # creates data/auth.log and data/access.log
python -m loganalyzer --auth data/auth.log --web data/access.log
python -m loganalyzer --auth data/auth.log --format json --out report.json
```

Sample output on the generated logs (379 auth events, 443 web events):

```
| Severity | Rule                   | Source IP      | Count | MITRE     |
| high     | ssh_brute_force        | 203.0.113.50   | 60    | T1110     |
| high     | password_spraying      | 203.0.113.77   | 10    | T1110.003 |
| high     | success_after_failures | 203.0.113.99   | 8     | T1078     |
| high     | sql_injection_attempt  | 203.0.113.140  | 3     | T1190     |
| medium   | web_scanning           | 203.0.113.120  | 40    | T1595.002 |
| medium   | scanner_user_agent     | 203.0.113.140  | 3     | T1595     |
```

## Tests

```bash
pip install -r requirements.txt
pytest -q
```

13 tests cover the parsers, each rule (including negative cases such as slow, spread-out failures and benign traffic), and an end-to-end run that checks the generated attack scenarios are found and the benign IPs stay clean.

## Project layout

```
loganalyzer/   parsers.py  detections.py  report.py  cli.py  models.py
scripts/       generate_sample_logs.py
tests/         test_loganalyzer.py
data/          generated sample logs
```

## Notes and limitations

- **All sample data is synthetic.** `generate_sample_logs.py` creates it with a fixed random seed, using the RFC 5737 documentation IP ranges. No real logs or real IPs are included.
- Detection is rule-based and threshold-driven, so it will miss slow-and-low attacks and can produce false positives on shared NAT addresses. It is a learning project, not a replacement for a SIEM.
- Syslog lines omit the year, so it is supplied with `--year`.
- Built with AI assistance (Claude); I reviewed and ran all of the code.

## Possible next steps

IP reputation enrichment, geolocation, a streaming/tail mode, and exporting alerts to a SIEM format.
