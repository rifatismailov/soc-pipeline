// ================================================================
// NODE 5: BUILD CLAUDE PROMPT
// Будує system + user prompt для Claude AI triage
// Якщо FP_CANDIDATE — додає попередження в промпт
// ================================================================

const d    = $input.first().json;
const rule = d.rule;
const data = d.data;

const fpNote = d.fpStatus === 'FP_CANDIDATE'
  ? `\n\n⚠️ NOTE: Pre-classifier flagged this as FP_CANDIDATE: ${d.fpReason}. Confirm or override.`
  : '';

const SYSTEM = `You are an expert SOC analyst. Analyze the Wazuh SIEM alert below and classify it.

Return ONLY a valid JSON object. No markdown fences, no prose, nothing else.

JSON schema:
{
  "verdict":            "fp" | "benign" | "suspicious" | "malicious" | "unknown",
  "confidence":         <float 0.0-1.0>,
  "severity":           "low" | "medium" | "high" | "critical",
  "summary":            "<one sentence, what happened>",
  "mitre_techniques":   ["T<id>", ...],
  "create_case":        <true|false>,
  "fp_reason":          "<why FP — only if verdict=fp, else empty string>",
  "suppressor_hint":    "<Wazuh rule XML field to suppress — only if verdict=fp, else empty string>",
  "recommended_action": "<what the analyst should do next>"
}

Classification rules:
- fp         → confirmed false positive: known-good software, legitimate admin action, Windows Defender scan artifact, standard service startup
- benign     → legitimate activity, no action needed
- suspicious → warrants investigation, could be an attack stage
- malicious  → high-confidence attack or active compromise
- unknown    → insufficient context

create_case = true  for: suspicious, malicious, unknown
create_case = false for: fp, benign

When verdict=fp, suppressor_hint must contain the Wazuh rule XML <field> condition to suppress this specific FP.`;

const USER = `Wazuh Alert:

Rule ID    : ${d.ruleId}
Rule Level : ${d.ruleLevel}/15
Description: ${rule.description || ''}
Groups     : ${JSON.stringify(rule.groups || [])}
MITRE      : ${JSON.stringify(rule.mitre || {})}
Agent      : ${d.agentName} (${d.agentIp})
Timestamp  : ${d.timestamp}
Corr-Key   : ${d.corrKey}${fpNote}

Alert data (JSON):
${JSON.stringify(data, null, 2)}`;

return [{
  json: {
    alertCtx: d,
    claudeReq: {
      model:      'claude-haiku-4-5-20251001',
      max_tokens: 1024,
      system:     SYSTEM,
      messages:   [{ role: 'user', content: USER }]
    }
  }
}];
