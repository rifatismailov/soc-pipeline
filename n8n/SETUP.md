# n8n Workflow Setup — SOC Triage Pipeline

## 1. Додай ANTHROPIC_API_KEY у .env

```bash
# На сервері n8n (10.10.67.10):
nano ~/soc-pipeline/.env
```

Додати рядок:
```
ANTHROPIC_API_KEY=sk-ant-api03-XXXX...
```

Отримати ключ: https://console.anthropic.com/settings/keys

Перезапусти контейнер щоб підтягнути нову змінну:
```bash
cd ~/soc-pipeline
docker compose down && docker compose up -d
```

---

## 2. Імпортуй workflow в n8n

1. Відкрий n8n: `https://10.10.67.10:5678`
2. Left sidebar → **Workflows** → **Add workflow** → **Import from file**
3. Вибери файл `n8n/workflow-soc-triage.json`

---

## 3. Налаштуй webhook-path

Після імпорту відкрий вузол **Wazuh Alert** (Webhook node):
- HTTP Method: `POST`
- Path: `wazuh-alerts`
- Response Mode: `Last node`

Це має матчитись з URL у Wazuh: `https://10.10.67.10:5678/webhook/wazuh-alerts`

---

## 4. Перевір ANTHROPIC_API_KEY у вузлі Claude AI Triage

Відкрий вузол **Claude AI Triage** (HTTP Request):
- URL: `https://api.anthropic.com/v1/messages`
- Method: `POST`
- Headers:
  - `x-api-key` = `{{ $env.ANTHROPIC_API_KEY }}`
  - `anthropic-version` = `2023-06-01`
  - `content-type` = `application/json`
- Body: JSON → `={{ JSON.stringify($json.claudeReq) }}`

> n8n читає `ANTHROPIC_API_KEY` з .env через `$env.ANTHROPIC_API_KEY`

---

## 5. FP Journal

False positives зберігаються у файл усередині Docker volume:
```
/home/node/.n8n/fp-journal/fp_journal.jsonl
```

На хості це:
```bash
docker exec n8n cat /home/node/.n8n/fp-journal/fp_journal.jsonl
```

Або через volume (шукай де docker зберігає `n8n_data`):
```bash
docker inspect n8n | grep -A5 Mounts
```

Кожен запис — одна JSON-лінія:
```json
{
  "ts": "2026-09-10T12:00:00Z",
  "rule_id": "100882",
  "agent_name": "D-2340850",
  "fp_reason": "Windows Defender loading MpOAV.dll during routine scan",
  "suppressor_hint": "<field name='win.eventdata.image' type='pcre2'>(?i)MpOAV\\.dll</field>",
  "recommended_action": "Add suppressor rule to local_rules.xml"
}
```

---

## 6. Dagobert (поки placeholder)

Вузол **Create Dagobert Case** наразі вказує на `http://dagobert:8080/api/cases`.

Коли Dagobert буде розгорнуто — він стане доступний по internal Docker DNS `dagobert`.

Поки що цей вузол повертатиме помилку з'єднання — це нормально, FP journal і логування працюватимуть.

**Тимчасово відключити Dagobert вузол:**
- У вузлі **Verdict Router** — вихід `create_case` → disconnect або замінити на NoOp

---

## 7. Publish і тест

1. Натисни **Publish** (top-right) щоб активувати webhook production URL
2. Надішли тестовий alert вручну:
```bash
curl -k -X POST https://10.10.67.10:5678/webhook/wazuh-alerts \
  -H "Content-Type: application/json" \
  -d '{
    "source": "wazuh",
    "timestamp": "2026-09-10T12:00:00Z",
    "alert_id": "test-001",
    "agent": {"id": "001", "name": "test-agent", "ip": "10.0.0.1"},
    "rule": {"id": "100882", "level": 10, "description": "Test DLL load", "groups": ["windows"], "mitre": {}},
    "data": {"win": {"eventdata": {"image": "C:\\Windows\\System32\\MpOAV.dll"}}}
  }'
```

3. Перевір **Executions** — повинен бути Success з verdict у відповіді

---

## Результат після налаштування

```
Wazuh alert (level≥10, rule≥100500)
    ↓
n8n Webhook
    ↓
Normalize → Build Prompt
    ↓
Claude API (claude-haiku-4-5) — ~1-2 sec
    ↓
Parse JSON verdict
    ↓
Switch on verdict:
  fp         → FP Journal (JSONL file) → analyst adds suppressor
  benign     → log only
  suspicious │
  malicious  │→ Dagobert Case (create)
  unknown    │
```
