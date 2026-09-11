// ================================================================
// NODE 1: DEDUP
// Verified fields: alerts_20260910_1657.json (659 events)
// ВАЖЛИВО: Always Output Data = OFF
//
// ВИПРАВЛЕНО vs ChatGPT:
//   - imageLoaded відсутній у реальних alerts → прибрано
//   - destinationIp / sourceAddress відсутні → тільки ipAddress
//   - commandLine НЕ обрізаємо → enc payload різниця може бути в кінці
//   - agentId = agent.id || agent.name (агент може не мати id)
// ================================================================

const TTL_MS = 5 * 60 * 1000;

const raw   = $input.first().json;
const alert = raw.body ?? raw;

const rule      = alert.rule  || {};
const agent     = alert.agent || {};
const eventdata = alert.data?.win?.eventdata || {};

const ruleId  = String(rule.id   || '');
const agentId = String(agent.id  || agent.name || '');

function norm(v) {
  return String(v || '').toLowerCase().replace(/\\/g, '\\').trim();
}

function buildKey() {
  const base = `${agentId}::${ruleId}`;

  // Authentication events — реальні поля: ipAddress, targetUserName, subjectUserName
  // (destinationIp / sourceAddress / authPkg відсутні у реальних alerts!)
  if (ruleId === '100820' || ruleId === '100870') {
    return [
      base,
      norm(eventdata.ipAddress),
      norm(eventdata.targetUserName),
      norm(eventdata.subjectUserName)
    ].join('::');
  }

  // SeDebugPrivilege — реальне поле: subjectUserName тільки
  if (ruleId === '100830') {
    return `${base}::${norm(eventdata.subjectUserName)}`;
  }

  // LSASS access — реальні поля: sourceImage, targetImage, grantedAccess
  if (ruleId === '100740') {
    return [base, norm(eventdata.sourceImage), norm(eventdata.grantedAccess)].join('::');
  }

  // CreateRemoteThread — реальні поля: sourceImage, targetImage
  if (ruleId === '100880' || ruleId === '100881') {
    return [base, norm(eventdata.sourceImage), norm(eventdata.targetImage)].join('::');
  }

  // DLL/Network events — imageLoaded ВІДСУТНІЙ у реальних alerts, тільки image
  // (ChatGPT помилково використовував imageLoaded → мертвий код)
  if (['100882', '100883', '100884', '100825', '100826'].includes(ruleId)) {
    return `${base}::${norm(eventdata.image)}`;
  }

  // 100743 Persistence — eventdata порожній, кожна подія унікальна по суті
  if (ruleId === '100743') {
    return `${base}::${alert.alert_id || alert.id || Date.now()}`;
  }

  // Process events (100713, 100716, 100723, 100810 та решта)
  // Реальні поля: image, commandLine
  // НЕ обрізаємо commandLine — PowerShell -enc відрізняються в кінці base64
  return `${base}::${norm(eventdata.image)}::${norm(eventdata.commandLine)}`;
}

const key   = buildKey();
const store = $getWorkflowStaticData('global');
const seen  = store.dedup || {};
const now   = Date.now();

for (const k of Object.keys(seen)) {
  if (now - seen[k] > TTL_MS) delete seen[k];
}

if (seen[key]) {
  store.dedup = seen;
  return [];
}

seen[key] = now;
store.dedup = seen;

alert.soc = {
  dedup_key:    key,
  dedup_ttl_s:  300,
  dedup_status: 'NEW'
};

return [{ json: alert }];
