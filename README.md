# SOC Pipeline — n8n + Dagobert

## Структура

```
soc-pipeline/
├── install-docker.sh      # встановлення Docker Engine (Ubuntu 22.04/24.04)
├── docker-compose.yml     # n8n + Dagobert
├── .env.example           # змінні для n8n (скопіювати в .env)
├── dagobert.env.example   # змінні для Dagobert (скопіювати в dagobert.env)
└── README.md
```

---

## Крок 1 — Встановити Docker

```bash
sudo bash install-docker.sh
# після завершення — перелогінитись або:
newgrp docker
```

---

## Крок 2 — Підготувати конфіги

```bash
cp .env.example .env
cp dagobert.env.example dagobert.env
```

Відредагувати `.env`:
- `N8N_BASIC_AUTH_PASSWORD` — надійний пароль
- `N8N_ENCRYPTION_KEY` — `openssl rand -hex 32`
- `WEBHOOK_URL` — реальний IP/FQDN VM

Відредагувати `dagobert.env`:
- за потреби додати API ключі (VirusTotal, AbuseIPDB)

---

## Крок 3 — Запустити контейнери

```bash
docker compose up -d
docker compose ps
docker compose logs -f
```

Перевірити:
- n8n: `http://YOUR_VM_IP:5678`
- Dagobert: `http://YOUR_VM_IP:8080`

---

## Крок 4 — Створити першого користувача Dagobert

```bash
docker exec -it dagobert ./dagobert create-user
```

---

## Крок 5 — Створити API key для n8n→Dagobert інтеграції

```bash
docker exec -it dagobert ./dagobert create-api-key "n8n-integration"
```

Скопіювати отриманий ключ (`dgb_...`) і вставити в `.env` як `DAGOBERT_API_KEY`.
Також додати його в n8n Credentials (Header Auth: `X-API-Key`).

---

## Зупинка / Перезапуск / Оновлення

```bash
# зупинити
docker compose down

# перезапустити
docker compose restart

# оновити образи (дані зберігаються у volumes)
docker compose pull
docker compose up -d
```

---

## Backup

```bash
# Dagobert SQLite
docker run --rm \
  -v dagobert_data:/source:ro \
  -v $(pwd)/backup:/backup \
  alpine tar czf /backup/dagobert-$(date +%Y%m%d).tar.gz -C /source .

# n8n workflows + credentials
docker run --rm \
  -v n8n_data:/source:ro \
  -v $(pwd)/backup:/backup \
  alpine tar czf /backup/n8n-$(date +%Y%m%d).tar.gz -C /source .
```

---

## Dagobert API (з n8n або curl)

```
Base URL (зсередини Docker): http://dagobert:8080
Base URL (з хоста):          http://YOUR_VM_IP:8080

Auth header: X-API-Key: dgb_...

GET  /cases/                        # всі кейси
POST /cases/new                     # новий кейс
GET  /cases/{id}                    # деталі кейсу
POST /cases/{id}/events/new         # новий event (Timeline)
POST /cases/{id}/indicators/new     # новий IOC
POST /cases/{id}/assets/new         # новий хост
POST /cases/{id}/notes/new          # нотатка
POST /cases/{id}/tasks/new          # задача для аналітика
```

Мінімальний payload для нового кейсу:
```json
{
  "ID": "CASE-2026-000001",
  "Name": "Suspicious PowerShell execution"
}
```

---

## Мережева схема

```
[Wazuh] ──────► [n8n :5678] ──► AI (Claude API)
                     │
                     └──────► [Dagobert :8080]
                                    │
                               dagobert_data (SQLite)
```

n8n звертається до Dagobert через Docker-мережу `soc-net`:
`http://dagobert:8080` — без необхідності відкривати порт 8080 назовні.

---

## Troubleshooting

```bash
# Переглянути логи конкретного контейнера
docker compose logs n8n
docker compose logs dagobert

# Зайти в контейнер
docker exec -it n8n sh
docker exec -it dagobert sh

# Перевірити ресурси
docker stats

# Перевірити volumes
docker volume ls
docker volume inspect soc-pipeline_dagobert_data
```
