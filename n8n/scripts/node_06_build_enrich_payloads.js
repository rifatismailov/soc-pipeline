// ================================================================
// NODE 6: BUILD ENRICH PAYLOADS
// ================================================================
//
// Призначення:
//   Гілка "новий кейс" — будує payload для первинного наповнення
//   щойно створеного кейсу в Dagobert: Event, Asset, Indicator, Note.
//   Також зберігає новий кейс в in-memory caseCache.
//
// Що робить:
//   1. caseCache → WorkflowStaticData
//      Після створення кейсу зберігаємо { id, name, ts } в кеш
//      щоб наступні алерти від того ж хоста не робили зайвий
//      GET /cases, а одразу йшли на Update.
//   2. Event   → /cases/{id}/events/new  (form-urlencoded)
//      Перший event для нового кейсу. Тип з MITRE tactic.
//      Raw = повний eventdata JSON.
//   3. Asset   → /cases/{id}/assets/new  (form-urlencoded)
//      Хост-агент: Name=agentName, Type=Desktop, Addr=agentIp.
//      Notes містить Agent ID + перший алерт + timestamp.
//   4. Indicator → /cases/{id}/indicators/new (form-urlencoded)
//      Та сама логіка що в Node 5 (Update):
//        100820/100870 → source IP
//        100825/100826 → destination IP:port
//        PowerShell → commandLine
//        image → Path
//        fallback → опис правила
//   5. Note    → /cases/{id}/notes/new   (form-urlencoded)
//      Повний вміст без скорочень: rule, agent, MITRE, всі
//      eventdata поля, повний Windows event message.
//
// КРИТИЧНО: Dagobert sub-entity handlers викликають Decode() двічі на одному body stream.
// JSON режим отримує EOF при другому decode → 400. Form режим (ParseForm) кешує → обидва успішні.
//
// Вхід:  Create Case HTTP node → { ID, Name }
//        Find Existing Case → { ruleId, ruleLevel, agentName, ... }
// Вихід: { caseId, eventUrl, eventForm, assetUrl, assetForm,
//           indicatorUrl, indicatorForm, noteUrl, noteForm }
//
// ================================================================

const newCase = $input.first().json;
const d       = $('Find Existing Case').first().json;
const caseId  = newCase.ID;

const store = $getWorkflowStaticData('global');
const caseCache = store.caseCache || {};
caseCache[d.corrKey] = { id: caseId, name: newCase.Name, ts: Date.now() };
store.caseCache = caseCache;

const ed  = d.data?.win?.eventdata || {};
const sys = d.data?.win?.system    || {};
const sc  = d.data?.syscheck || d.alert?.full_alert?.syscheck || {};

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

const indicatorForm = `Value=${enc(iVal)}&Type=${enc(iType)}&Status=${enc(iStatus)}&TLP=${enc('TLP:AMBER')}&Source=${enc(iSource)}&Flagged=${iFlagged}`;

// ── Актив (Asset) ─────────────────────────────────────────────────────────────
const assetForm = [
  `Name=${enc(d.agentName)}`,
  `Type=Desktop`,
  `Status=${enc('Under investigation')}`,
  `Addr=${enc(d.agentIp || '')}`,
  `Notes=${enc('Wazuh Agent ID: ' + (d.agent?.id || '') + ' | First alert: [' + d.ruleId + '] ' + (d.rule.description || '') + ' | ' + new Date(d.timestamp).toISOString())}`,
].join('&');

return [{ json: {
  caseId,
  eventUrl:     `http://172.18.0.3:8080/cases/${caseId}/events/new`,
  assetUrl:     `http://172.18.0.3:8080/cases/${caseId}/assets/new`,
  indicatorUrl: `http://172.18.0.3:8080/cases/${caseId}/indicators/new`,
  noteUrl:      `http://172.18.0.3:8080/cases/${caseId}/notes/new`,

  eventForm: [
    `Time=${enc(new Date(d.timestamp).toISOString())}`,
    `Type=${enc(eventType)}`,
    `Event=${enc(eventDesc)}`,
    `Raw=${enc(JSON.stringify(rawObj))}`,
    `Source=Wazuh`,
    techPart,
  ].filter(Boolean).join('&'),

  assetForm,
  indicatorForm,

  noteForm: [
    `Title=${enc('[Wazuh] Rule ' + d.ruleId + ' — First Occurrence')}`,
    `Category=Wazuh`,
    `Description=${enc(noteDesc)}`,
  ].join('&'),
} }];
