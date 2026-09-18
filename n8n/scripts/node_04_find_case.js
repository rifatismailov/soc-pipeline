// ================================================================
// NODE 4: FIND EXISTING CASE
// ================================================================
//
// Призначення:
//   Визначає чи існує вже відкритий кейс у Dagobert для цього хоста.
//   Якщо є — повертає його ID і Name → іде гілка "Update".
//   Якщо немає — повертає порожній existingCaseId → іде гілка "Create".
//
// Логіка пошуку кейсу:
//   1. Спочатку перевіряємо WorkflowStaticData (in-memory cache):
//      caseCache[corrKey] = { id, name, ts }
//      TTL кешу = 4 години. Якщо запис є і не прострочений — не
//      звертаємось до Dagobert API зайвий раз.
//   2. Якщо в кеші немає — шукаємо в списку кейсів від попередньої
//      HTTP ноди (GET /cases): відкритий кейс з назвою [HOST] що
//      містить corrKey (IP агента).
//
// corrKey:
//   agent.ip → основний ключ кореляції.
//   Всі алерти від одного хоста (IP) → один кейс у Dagobert.
//   Назва кейсу: "[HOST] <agentName> (<agentIp>)"
//
// Вхід:
//   Normalize Alert → { corrKey, agentName, agentIp, ruleId, ... }
//   HTTP GET /cases → масив кейсів { ID, Name, Closed, ... }
//
// Вихід:
//   { ...всі поля з Normalize, existingCaseId, existingCaseName }
//   existingCaseId = '' → гілка Create New Case
//   existingCaseId = 'XxXxX' → гілка Update Existing Case
//
// ================================================================

const d       = $('Normalize Alert').first().json;
const corrKey = d.corrKey;

// ── Cache lookup ──────────────────────────────────────────────────────────────
const store     = $getWorkflowStaticData('global');
const caseCache = store.caseCache || {};
const now       = Date.now();

// Прибираємо записи старші за 4 години
for (const k of Object.keys(caseCache)) {
  if (now - caseCache[k].ts > 4 * 60 * 60 * 1000) delete caseCache[k];
}
store.caseCache = caseCache;

// Якщо є в кеші — повертаємо одразу
if (caseCache[corrKey]) {
  return [{ json: {
    ...d,
    existingCaseId:   caseCache[corrKey].id,
    existingCaseName: caseCache[corrKey].name,
  } }];
}

// ── API lookup ────────────────────────────────────────────────────────────────
const raw      = $input.first().json;
const caseList = Array.isArray(raw.body) ? raw.body : [];

const existing = caseList.find(c =>
  !c.Closed &&
  typeof c.Name === 'string' &&
  c.Name.startsWith('[HOST]') &&
  c.Name.includes(corrKey)
);

return [{ json: {
  ...d,
  existingCaseId:   existing ? existing.ID   : '',
  existingCaseName: existing ? existing.Name : '',
} }];
