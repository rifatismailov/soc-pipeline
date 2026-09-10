#!/usr/bin/env python3
"""
Wazuh → n8n Custom Integration
Розміщення: /var/ossec/integrations/custom-n8n.py
Права:       chmod 750 custom-n8n.py && chown root:wazuh custom-n8n.py
"""

import sys
import json
import urllib.request
import urllib.error
import ssl
import os
from datetime import datetime

# ── Конфіг ────────────────────────────────────────────────────────────────────

# Мінімальний рівень alert для відправки (можна змінити в ossec.conf через <level>)
MIN_LEVEL = 10

# Тільки наші custom правила (100500+); 0 = всі правила
CUSTOM_RULE_MIN_ID = 100500

# Таймаут запиту до n8n (сек)
REQUEST_TIMEOUT = 10

# ── Logging ───────────────────────────────────────────────────────────────────

LOG_FILE = "/var/ossec/logs/integrations/custom-n8n.log"

def log(msg: str):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{ts} UTC | {msg}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # Wazuh передає аргументи: alert_file api_key hook_url
    if len(sys.argv) < 4:
        log(f"ERROR: wrong args count: {sys.argv}")
        sys.exit(1)

    alert_file = sys.argv[1]
    # sys.argv[2] = api_key (не використовується, автентифікація через n8n)
    hook_url   = sys.argv[3]

    # Читаємо alert
    try:
        with open(alert_file) as f:
            alert = json.load(f)
    except Exception as e:
        log(f"ERROR reading alert file {alert_file}: {e}")
        sys.exit(1)

    rule    = alert.get("rule", {})
    rule_id = int(rule.get("id", 0))
    level   = int(rule.get("level", 0))

    # Фільтр: тільки custom правила з достатнім рівнем
    if CUSTOM_RULE_MIN_ID > 0 and rule_id < CUSTOM_RULE_MIN_ID:
        log(f"SKIP rule_id={rule_id} (< {CUSTOM_RULE_MIN_ID})")
        sys.exit(0)

    if level < MIN_LEVEL:
        log(f"SKIP rule_id={rule_id} level={level} (< {MIN_LEVEL})")
        sys.exit(0)

    # Формуємо payload для n8n
    payload = {
        "source":      "wazuh",
        "timestamp":   alert.get("timestamp", ""),
        "alert_id":    alert.get("id", ""),
        "agent": {
            "id":   alert.get("agent", {}).get("id", ""),
            "name": alert.get("agent", {}).get("name", ""),
            "ip":   alert.get("agent", {}).get("ip", ""),
        },
        "rule": {
            "id":          str(rule_id),
            "level":       level,
            "description": rule.get("description", ""),
            "groups":      rule.get("groups", []),
            "mitre": {
                "id":      rule.get("mitre", {}).get("id", []),
                "tactic":  rule.get("mitre", {}).get("tactic", []),
                "technique": rule.get("mitre", {}).get("technique", []),
            },
        },
        "data":        alert.get("data", {}),
        "full_alert":  alert,
    }

    body = json.dumps(payload).encode("utf-8")

    # SSL context — n8n використовує self-signed cert
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    req = urllib.request.Request(
        hook_url,
        data    = body,
        headers = {
            "Content-Type": "application/json",
            "User-Agent":   "Wazuh-n8n-integration/1.0",
        },
        method = "POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ctx) as resp:
            status = resp.status
            log(f"OK rule_id={rule_id} level={level} agent={payload['agent']['name']} status={status}")
    except urllib.error.HTTPError as e:
        log(f"ERROR HTTP {e.code} rule_id={rule_id}: {e.reason}")
        sys.exit(1)
    except urllib.error.URLError as e:
        log(f"ERROR URL rule_id={rule_id}: {e.reason}")
        sys.exit(1)
    except Exception as e:
        log(f"ERROR rule_id={rule_id}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
