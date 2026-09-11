// ================================================================
// NODE 3: NORMALIZE ALERT
// Розпаковує поля alert для зручного використання в наступних нодах
// Передає soc metadata від DEDUP і FP Classifier далі
// ================================================================

const raw = $input.first().json;
const alert = raw.body ?? raw;

const agent = alert.agent || {};
const rule  = alert.rule  || {};
const data  = alert.data  || {};
const soc   = alert.soc   || {};

const corrKey = `${agent.ip || agent.id}::${rule.id}`;

return [{
  json: {
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
  }
}];
