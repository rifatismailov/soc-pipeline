// ================================================================
// NODE 2: FP CLASSIFIER
// Вся FP логіка керується через Dagobert UI (/fp-rules/).
// Ця нода: захист NEVER_DROP + динамічні правила Dagobert + PASS.
// Жодної жорсткої per-rule логіки тут — нові паттерни додавати через Dagobert.
// ВАЖЛИВО: Always Output Data = OFF
// ================================================================

const alert     = $('DEDUP').first().json;
const rule      = alert.rule  || {};
const eventdata = alert.data?.win?.eventdata || {};
const syscheck  = alert.data?.syscheck || alert.alert?.full_alert?.syscheck || {};

const ruleId = String(rule.id    || '');
const level  = Number(rule.level || 0);

function norm(v) { return String(v || '').toLowerCase().replace(/\//g, '\\').trim(); }

// FP правила з Dagobert API (нода Get FP Rules передає дані в цю ноду)
const _dynRules = $input.all().map(i => i.json).filter(r => r && r.field);

// Карта полів: назва поля Dagobert → нормалізоване значення події
const _fieldMap = {
  image:             norm(eventdata.image              || ''),
  commandLine:       norm(eventdata.commandLine        || ''),
  sourceImage:       norm(eventdata.sourceImage        || ''),
  targetImage:       norm(eventdata.targetImage        || ''),
  imageLoaded:       norm(eventdata.imageLoaded        || ''),
  parentImage:       norm(eventdata.parentImage        || ''),
  parentCommandLine: norm(eventdata.parentCommandLine  || ''),
  startModule:       norm(eventdata.startModule        || ''),
  startFunction:     norm(eventdata.startFunction      || ''),
  subjectUserName:   norm(eventdata.subjectUserName    || ''),
  targetUserName:    norm(eventdata.targetUserName     || ''),
  targetDomainName:  norm(eventdata.targetDomainName   || ''),
  grantedAccess:     norm(eventdata.grantedAccess      || ''),
  destinationIp:     norm(eventdata.destinationIp      || ''),
  destinationPort:   norm(eventdata.destinationPort    || ''),
  ipAddress:         norm(eventdata.ipAddress          || ''),
  workstationName:   norm(eventdata.workstationName    || ''),
  targetServerName:  norm(eventdata.targetServerName   || ''),
  callTrace:         norm(eventdata.callTrace          || ''),
  signatureStatus:   norm(eventdata.signatureStatus    || ''),
  registryPath:      norm(syscheck.path                || ''),
  filePath:          norm(syscheck.path                || ''),
  agentName:         norm(alert.agent?.name            || ''),
  agentIp:           norm(alert.agent?.ip              || ''),
};

// Правила що НІКОЛИ не можна авто-дропати як FP — примусово FP_CANDIDATE
const NEVER_DROP = new Set([
  '100740','100741','100742','100744',
  '100730','100731',
  '100743',
  '100750',
  '100780','100782','100783','100786','100787',
  '100795','100796','100798','100799',
  '100824',
  '100841','100842','100843',
  '100880',
]);

function classify() {
  for (const r of _dynRules) {
    if (r.rule_ids && r.rule_ids.length && !r.rule_ids.includes(ruleId)) continue;
    const val   = _fieldMap[r.field] || '';
    const check = (r.value || '').toLowerCase();
    let match = false;
    if      (r.op === 'includes')   match = val.includes(check);
    else if (r.op === 'endsWith')   match = val.endsWith(check);
    else if (r.op === 'startsWith') match = val.startsWith(check);
    else if (r.op === 'equals')     match = val === check;
    else if (r.op === 'regex')      match = new RegExp(r.value, 'i').test(val);
    if (match) return { status: r.status || 'FP', reason: '[dyn] ' + (r.reason || r.field + ' ' + r.op + ' ' + r.value) };
  }
  return { status: 'PASS', reason: '' };
}

const result = classify();

if (NEVER_DROP.has(ruleId) && result.status === 'FP') {
  result.status = 'FP_CANDIDATE';
  result.reason = '[NEVER_DROP] ' + result.reason;
}

alert.soc = {
  ...(alert.soc || {}),
  fp_status:          result.status,
  fp_reason:          result.reason,
  requires_ai_review: result.status !== 'FP',
};

if (result.status === 'FP') {
  try {
    const fs = require('fs'), path = require('path');
    const dir = '/home/node/.n8n/fp-journal';
    fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(
      path.join(dir, 'fp_journal.jsonl'),
      JSON.stringify({ ts: new Date().toISOString(), source: 'n8n_node2', rule_id: ruleId, level, agent: alert.agent?.name || '', fp_reason: result.reason }) + '\n'
    );

  } catch(e) {}
  return [];
}
return [{ json: alert }];
