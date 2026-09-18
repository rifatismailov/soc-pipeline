// ================================================================
// NODE 1: DEDUP
// n8n Code node — виконується для кожного алерту що приходить з Wazuh
//
// Призначення:
//   Відсіює дублікати алертів протягом TTL вікна (5 хвилин).
//   Wazuh може згенерувати десятки однакових алертів за секунди
//   (mimikatz відкриває LSASS в циклі, LOLBin з'єднується кожну хвилину і т.д.).
//   Без dedup pipeline і Dagobert отримували б спам замість одного інциденту.
//
// Як працює:
//   1. Для кожного алерту будується строковий ключ (buildKey)
//      що описує "цю конкретну загрозу від цього агента"
//   2. Ключ перевіряється в WorkflowStaticData (глобальний стор n8n)
//   3. Якщо ключ вже є і не прострочений → алерт кидається (return [])
//   4. Якщо новий → зберігається, алерт іде далі з полем alert.soc
//
// Вхід:  один Wazuh alert JSON (raw.body або raw)
// Вихід: [] якщо дублікат | [{ json: alert }] якщо новий
//
// ВАЖЛИВО в n8n: Always Output Data = OFF
//   (інакше n8n передає порожній об'єкт замість порожнього масиву)
//
// Verified fields: alerts_20260910_1657.json (659 events)
// ================================================================

// Час життя запису в seen-сторі: 5 хвилин
const TTL_MS = 5 * 60 * 1000;

// --- Розпаковка алерту ---
// Wazuh надсилає алерт напряму як JSON (top-level: timestamp, rule, agent...).
// n8n Webhook нода зазвичай передає його в $input.first().json без обгортки.
// Але якщо POST прийшов з Content-Type: application/x-www-form-urlencoded
// (або через деякі проксі/Logstash), n8n загортає тіло в { body: {...} }.
// raw.body ?? raw — захисний fallback: якщо body є — беремо його, інакше raw.
const raw   = $input.first().json;
const alert = raw.body ?? raw;

const rule      = alert.rule  || {};
const agent     = alert.agent || {};
const eventdata = alert.data?.win?.eventdata || {};  // Sysmon/Security eventdata (може бути відсутній)

const ruleId  = String(rule.id   || '');
const agentId = String(agent.id  || agent.name || '');  // agent.id — числовий ID, agent.name — fallback

// ----------------------------------------------------------------
// norm(v) — нормалізація поля для включення в dedup-ключ
//
// Проблема: Wazuh/Sysmon повертає шляхи і імена в різному регістрі
// залежно від версії агента і ОС. Щоб C:\Windows\lsass.exe і
// c:\windows\lsass.exe давали один і той самий ключ — приводимо
// до нижнього регістру. trim() прибирає випадкові пробіли.
//
// Backslash не чіпаємо: Sysmon завжди дає \ (не /), тому
// нормалізація роздільника не потрібна — ключ буде консистентним.
// ----------------------------------------------------------------
function norm(v) {
  return String(v || '').toLowerCase().trim();
}

// ----------------------------------------------------------------
// KEY_FIELDS — таблиця: ruleId → функція що повертає масив полів
//
// Різні rule ID детектують різні типи атак, тому і поля для ключа
// різні. Логіка відбору полів: "мінімальний набір що однозначно
// ідентифікує один інцидент протягом 5 хвилин".
//
// Щоб додати новий rule — достатньо одного рядка тут.
// Функцію buildKey() чіпати не треба.
//
// Формат ключа після join: "agentId::ruleId::field1::field2::..."
// ----------------------------------------------------------------
const KEY_FIELDS = {

  // 100820: Windows Explicit Credential Logon (Event 4648)
  //   Атакуючий явно вказує credentials для lateral movement.
  //   Один інцидент = один IP + один target user.
  //   subjectUserName — хто ініціював (може бути SYSTEM або атакуючий процес).
  '100820': e => [norm(e.ipAddress), norm(e.targetUserName), norm(e.subjectUserName)],

  // 100870: Pass-the-Hash (Event 4624, LogonType 3, NTLM)
  //   NTLM мережевий логон — класичний PtH індикатор.
  //   Унікальність: звідки прийшов логон (IP) + хто залогінився.
  '100870': e => [norm(e.ipAddress), norm(e.targetUserName), norm(e.subjectUserName)],

  // 100830: SeDebugPrivilege assigned (Event 4672)
  //   Mimikatz і більшість injectors запитують SeDebugPrivilege перед роботою.
  //   Унікальність: якому юзеру присвоєно привілей.
  '100830': e => [norm(e.subjectUserName)],

  // 100740: LSASS memory access (Sysmon Event 10 — ProcessAccess)
  //   Процес відкриває LSASS з правами читання пам'яті (credential dump).
  //   Унікальність: який процес (sourceImage) + з якими правами (grantedAccess).
  //   Без grantedAccess: один і той самий процес міг би відкрити LSASS
  //   з різними правами — це різні події.
  '100740': e => [norm(e.sourceImage), norm(e.grantedAccess)],

  // 100880: CreateRemoteThread CRITICAL (Sysmon Event 8, підозрілий source)
  // 100881: CreateRemoteThread стандартний (Sysmon Event 8)
  //   Process injection через CreateRemoteThread.
  //   Унікальність: хто інжектує (sourceImage) → в який процес (targetImage).
  '100880': e => [norm(e.sourceImage), norm(e.targetImage)],
  '100881': e => [norm(e.sourceImage), norm(e.targetImage)],

  // 100882: DLL завантажена з user-writable шляху (Sysmon Event 7 — ImageLoad)
  //   DLL hijacking або malware що дропнув DLL в AppData/Temp/Downloads.
  //   Унікальність: який процес завантажив підозрілу DLL.
  '100882': e => [norm(e.image)],

  // 100883: DLL з невалідним або відсутнім підписом (Sysmon Event 7)
  //   ~895 алертів/день на продакшені — без dedup заспамив би pipeline.
  //   Унікальність: який процес завантажив непідписану DLL.
  '100883': e => [norm(e.image)],

  // 100884: LOLBin завантажує підозрілу DLL (Sysmon Event 7)
  //   Легітимний системний бінарник (rundll32, regsvr32, mshta...)
  //   використовується для завантаження шкідливого коду.
  '100884': e => [norm(e.image)],

  // 100825: LOLBin initiated outbound connection (Sysmon Event 3)
  //   Системний бінарник з'єднується назовні — C2 індикатор.
  // 100826: Outbound connection з підозрілої директорії (Sysmon Event 3)
  //   Процес з Temp/AppData/Downloads з'єднується назовні.
  //   Обидва: unікальність = який процес робить з'єднання.
  '100825': e => [norm(e.image)],
  '100826': e => [norm(e.image)],

  // 100743: Persistence mechanism (Run key / Startup folder modified)
  //   КОЖНА зміна Run key — окремий факт що треба розслідувати.
  //   Дедуплікація заборонена: використовуємо унікальний alert ID.
  //   Date.now() — останній fallback якщо Wazuh не передав ID.
  '100743': _e => [alert.id || alert.alert_id || String(Date.now())],
};

// ----------------------------------------------------------------
// buildKey() — будує рядковий dedup-ключ для поточного алерту
//
// Структура ключа: "agentId::ruleId::field1::field2::..."
//   agentId — прив'язує ключ до конкретного хоста
//   ruleId  — тип загрози
//   fields  — що саме сталось (залежить від типу загрози)
//
// Fallback (rule не в KEY_FIELDS):
//   image + commandLine — підходить для більшості process-based rules
//   що не потребують спеціальної логіки.
// ----------------------------------------------------------------
function buildKey() {
  const base   = `${agentId}::${ruleId}`;
  const schema = KEY_FIELDS[ruleId];

  if (schema) return [base, ...schema(eventdata)].join('::');

  return [base, norm(eventdata.image), norm(eventdata.commandLine)].join('::');
}

// ================================================================
// Dedup logic
// ================================================================

const key = buildKey();

// $getWorkflowStaticData('global') — персистентний стор n8n
// Живе поки запущений workflow. store.dedup = { key: timestamp, ... }
const store = $getWorkflowStaticData('global');
const seen  = store.dedup || {};
const now   = Date.now();

// Очищення прострочених записів (TTL = 5 хвилин)
// Без цього seen росте необмежено і з часом уповільнює ноду
for (const k of Object.keys(seen)) {
  if (now - seen[k] > TTL_MS) delete seen[k];
}

// Якщо ключ вже бачили — дублікат, кидаємо алерт
if (seen[key]) { store.dedup = seen; return []; }

// Новий алерт — зберігаємо ключ і пропускаємо далі
seen[key] = now;
store.dedup = seen;

// Додаємо мета-поле для діагностики і наступних нод pipeline
alert.soc = {
  dedup_key:    key,   // для debug і логування
  dedup_ttl_s:  300,   // скільки секунд цей ключ активний
  dedup_status: 'NEW', // наступні ноди можуть перевірити статус
};

return [{ json: alert }];
