// ================================================================
// NODE 5: BUILD UPDATE PAYLOADS
// ================================================================
//
// Призначення:
//   Гілка "існуючий кейс" — будує payload для оновлення кейсу
//   в Dagobert: додає Event, Indicator, Note і оновлює Summary.
//
// Що робить:
//   1. Event   → /cases/{id}/events/new  (form-urlencoded)
//      Тип береться з MITRE tactic алерту.
//      Raw = повний eventdata JSON без скорочень.
//   2. Note    → /cases/{id}/notes/new   (form-urlencoded)
//      Повний вміст: rule, agent, MITRE, всі eventdata поля,
//      повний Windows event message — нічого не обрізається.
//   3. Indicator → /cases/{id}/indicators/new (form-urlencoded)
//      Логіка вибору індикатора по rule ID:
//        100820/100870 → source IP (логон з зовні)
//        100825/100826 → destination IP:port (outbound C2)
//        PowerShell rules → commandLine
//        інші з image → шлях до процесу (Path)
//        fallback → опис правила
//   4. Case update → /cases/{id}  (JSON)
//      Оновлює Name, Severity, Summary з повним контекстом алерту.
//
// КРИТИЧНО: sub-endpoints потребують form-urlencoded (баг подвійного decode в Dagobert)
// POST /cases/{id} (update) використовує JSON — це НЕ sub-entity handler
//
// Вхід:  Find Existing Case → { existingCaseId, ruleId, ruleLevel, ... }
// Вихід: { eventUrl, eventForm, noteUrl, noteForm,
//           indicatorUrl, indicatorForm, caseUpdateUrl, caseUpdateJson }
//
// ================================================================

const d       = $input.first().json;
const caseId  = d.existingCaseId;
const ed      = d.data?.win?.eventdata || {};
const sys     = d.data?.win?.system    || {};
const sc      = d.data?.syscheck || d.alert?.full_alert?.syscheck || {};

const enc = encodeURIComponent;

// ── Severity ──────────────────────────────────────────────────────────────────
const sev = d.ruleLevel >= 12 ? 'High' : d.ruleLevel >= 6 ? 'Medium' : 'Low';

// ── MITRE ─────────────────────────────────────────────────────────────────────
const mitre     = d.rule.mitre || {};
const mitreIds  = mitre.id        || [];
const mitreTech = mitre.technique || [];
const mitreTac  = mitre.tactic    || [];

// Відображення Wazuh tactic (title-case) → Dagobert Event Type enum
const tacticToType = {
  'Credential Access':    'Credential Access',
  'Defense Evasion':      'Defense Evasion',
  'Discovery':            'Discovery',
  'Execution':            'Execution',
  'Exfiltration':         'Exfiltration',
  'Impact':               'Impact',
  'Initial Access':       'Initial Access',
  'Lateral Movement':     'Lateral Movement',
  'Persistence':          'Persistence',
  'Privilege Escalation': 'Privilege Escalation',
  'Reconnaissance':       'Reconnaissance',
  'Resource Development': 'Resource Development',
  'Collection':           'Collection',
  'Command and Control':  'C2',
};
const eventType = mitreTac.map(t => tacticToType[t]).find(Boolean) || 'Other';

// ── MITRE рядок для нотатки ───────────────────────────────────────────────────
const mitreStr = mitreIds.length
  ? mitreIds.map((id, i) => `${id} — ${mitreTech[i] || ''} (${mitreTac.join(', ')})`).join('\n  ')
  : 'N/A';

// ── Techniques для форми Event ────────────────────────────────────────────────
const techPart = mitreIds.length
  ? '&' + mitreIds.map(t => `Techniques=${enc(t)}`).join('&')
  : '';

// ── Всі поля eventdata (без фільтрації, без обрізання) ────────────────────────
const edLines = Object.entries(ed)
  .filter(([, v]) => v !== undefined && v !== null && v !== '')
  .map(([k, v]) => `  ${k}: ${v}`);

// ── Всі поля syscheck (без фільтрації, без обрізання) ─────────────────────────
const scLines = Object.entries(sc)
  .filter(([, v]) => v !== undefined && v !== null && v !== '')
  .map(([k, v]) => `  syscheck.${k}: ${v}`);

// ── Повне Windows event message (без обрізання) ───────────────────────────────
const sysMsg = sys.message
  ? `\n\n**Event Message (full):**\n${sys.message}`
  : '';

// ── Опис нотатки — повний вміст, нічого не обрізається ───────────────────────
const noteDesc = [
  `**Rule:** [${d.ruleId}] ${d.rule.description || d.ruleId}`,
  `**Level:** ${d.ruleLevel}/15  |  **Severity:** ${sev}`,
  `**Time:** ${new Date(d.timestamp).toISOString()}`,
  `**Agent:** ${d.agentName} (${d.agentIp}) — ID: ${d.agent?.id || ''}`,
  `**FP Status:** ${d.fpStatus}${d.fpReason ? ' — ' + d.fpReason : ''}`,
  `**Rule Groups:** ${(d.rule.groups || []).join(', ')}`,
  `\n**MITRE:**\n  ${mitreStr}`,
  sys.eventID
    ? `\n**Windows Event:**\n  EventID: ${sys.eventID}\n  Channel: ${sys.channel || ''}\n  Computer: ${sys.computer || ''}\n  Provider: ${sys.providerName || ''}`
    : '',
  (edLines.length || scLines.length)
    ? `\n**Event Data:**\n${[...edLines, ...scLines].join('\n')}`
    : '',
].filter(Boolean).join('\n') + sysMsg;

// ── Опис події ────────────────────────────────────────────────────────────────
const eventDesc = `[${d.ruleId}] ${d.rule.description || d.ruleId} — ${d.agentName} (${d.agentIp})`;

// ── Raw для Event: повний eventdata + syscheck ────────────────────────────────
const rawObj = Object.keys(sc).length > 0 ? { ...ed, syscheck: sc } : ed;

// ── Індикатор ─────────────────────────────────────────────────────────────────
const srcIp    = (ed.ipAddress      || '').trim();
const destIp   = (ed.destinationIp  || '').trim();
const destPort = (ed.destinationPort|| '').trim();
const cmdLine  = (ed.commandLine    || '').trim();
const imgFull  = (ed.image          || '').trim();
const imgName  = imgFull.split('\\').pop() || imgFull.split('/').pop();
const r        = d.ruleId;

let iVal = '', iType = 'Other', iStatus = 'Under investigation', iSource = '', iFlagged = false;

if ((r === '100820' || r === '100870') && srcIp && !['', '-', '::1', '127.0.0.1', d.agentIp].includes(srcIp)) {
  iVal    = srcIp;
  iType   = 'IP';
  iStatus = 'Suspicious';
  iSource = `[${r}] ${d.rule.description || r} | logon to ${d.agentName} as ${ed.targetUserName || '?'} from ${srcIp} via ${ed.authenticationPackageName || 'NTLM'}`;
  iFlagged = true;

} else if (r === '100825' || r === '100826') {
  const ip = destIp || srcIp;
  iVal    = destPort ? `${ip}:${destPort}` : ip;
  iType   = 'IP';
  iStatus = 'Suspicious';
  iSource = `[${r}] ${d.rule.description || r} | process: ${imgName} | agent: ${d.agentName}`;
  iFlagged = true;

} else if (['100720','100721','100722','100723','100724','100725','100726','100727'].includes(r) && cmdLine) {
  iVal    = cmdLine;
  iType   = 'Other';
  iStatus = 'Suspicious';
  iSource = `[${r}] ${d.rule.description || r} | agent: ${d.agentName}`;
  iFlagged = true;

} else if (imgName) {
  iVal    = imgFull;
  iType   = 'Path';
  iStatus = 'Under investigation';
  iSource = `[${r}] ${d.rule.description || r} | agent: ${d.agentName}`;
  iFlagged = false;

} else {
  iVal    = `[${r}] ${(d.rule.description || r)}`;
  iType   = 'Other';
  iStatus = 'Under investigation';
  iSource = `agent: ${d.agentName} (${d.agentIp})`;
  iFlagged = false;
}

const indicatorUrl  = iVal ? `http://172.18.0.3:8080/cases/${caseId}/indicators/new` : '';
const indicatorForm = iVal
  ? `Value=${enc(iVal)}&Type=${enc(iType)}&Status=${enc(iStatus)}&TLP=${enc('TLP:AMBER')}&Source=${enc(iSource)}&Flagged=${iFlagged}`
  : '';

// ── Summary (повний контекст) ─────────────────────────────────────────────────
const summaryParts = [
  `[${d.ruleId}] ${d.rule.description || d.ruleId}`,
  `Host: ${d.agentName} (${d.agentIp})`,
  `Severity: ${sev} (level ${d.ruleLevel}/15)`,
  mitreTac.length  ? `Tactics: ${mitreTac.join(', ')}` : '',
  mitreIds.length  ? `MITRE: ${mitreIds.join(', ')}` : '',
  ed.targetUserName ? `User: ${ed.targetUserName}` : '',
  srcIp             ? `Source IP: ${srcIp}` : '',
  `Time: ${new Date(d.timestamp).toISOString()}`,
].filter(Boolean).join(' | ');

return [{ json: {
  eventUrl:      `http://172.18.0.3:8080/cases/${caseId}/events/new`,
  noteUrl:       `http://172.18.0.3:8080/cases/${caseId}/notes/new`,
  indicatorUrl,
  indicatorForm,
  caseUpdateUrl: `http://172.18.0.3:8080/cases/${caseId}`,

  eventForm: [
    `Time=${enc(new Date(d.timestamp).toISOString())}`,
    `Type=${enc(eventType)}`,
    `Event=${enc(eventDesc)}`,
    `Raw=${enc(JSON.stringify(rawObj))}`,
    `Source=Wazuh`,
    techPart,
  ].filter(Boolean).join('&'),

  noteForm: [
    `Title=${enc('[Wazuh] Rule ' + d.ruleId + ' — ' + new Date(d.timestamp).toISOString().slice(0, 16).replace('T', ' '))}`,
    `Category=Wazuh`,
    `Description=${enc(noteDesc)}`,
  ].join('&'),

  caseUpdateJson: {
    Name:     d.existingCaseName,
    Severity: sev,
    Summary:  summaryParts,
  },
} }];
