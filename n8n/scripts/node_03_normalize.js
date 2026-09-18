// ================================================================
// NODE 3: NORMALIZE ALERT
// ================================================================
//
// Призначення:
//   Розпаковує alert після DEDUP і будує плоску структуру з
//   усіма ключовими полями на верхньому рівні. Наступні ноди
//   (Find Existing Case, Build Payloads) читають звідси — не з
//   вкладеного alert.rule.id, а просто d.ruleId.
//
// Вхід:
//   DEDUP → { timestamp, rule, agent, data, soc, ... }
//
// Вихід (плоска структура):
//   alert      — повний оригінальний об'єкт алерту
//   agent      — { id, name, ip }
//   rule       — { id, level, description, groups, mitre }
//   data       — { win: { eventdata, system }, syscheck, ... }
//   soc        — { dedup_key, fp_status, fp_reason, ... }
//   corrKey    — ключ кореляції: agent.ip або agent.id або agent.name
//                (використовується для пошуку/створення кейсу в Dagobert)
//   alertId    — унікальний ID алерту від Wazuh
//   timestamp  — час події
//   ruleId     — String (щоб порівнювати без Number/String плутанини)
//   ruleLevel  — Number
//   agentName  — ім'я хоста
//   agentIp    — IP агента
//   fpStatus   — PASS | FP | FP_CANDIDATE
//   fpReason   — пояснення від FP Classifier
//
// ================================================================

const alert = $input.first().json;

const agent = alert.agent || {};
const rule  = alert.rule  || {};
const data  = alert.data  || {};
const soc   = alert.soc   || {};

const corrKey = agent.ip || agent.id || agent.name;

return [{ json: {
  alert,
  agent,
  rule,
  data,
  soc,
  corrKey,
  alertId:   alert.id || alert.alert_id || '',
  timestamp: alert.timestamp || new Date().toISOString(),
  ruleId:    String(rule.id    || ''),
  ruleLevel: Number(rule.level || 0),
  agentName: agent.name || 'unknown',
  agentIp:   agent.ip   || '',
  fpStatus:  soc.fp_status || 'PASS',
  fpReason:  soc.fp_reason || '',
} }];
