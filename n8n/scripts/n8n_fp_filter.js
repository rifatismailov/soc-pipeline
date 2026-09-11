// ================================================================
// NODE 2: FP CLASSIFIER
// Verified fields: alerts_20260910_1657.json (659 events)
// ВАЖЛИВО: Always Output Data = OFF
//
// ВИПРАВЛЕНО vs ChatGPT:
//   - imageLoaded відсутній у реальних alerts → весь imgL-код прибрано
//   - parentImage відсутній у реальних alerts → прибрано
//   - grantedAccess: '0x1010' → '0x101000' (реальне значення!)
//   - Додано NEVER_DROP: ці rules ніколи не silent drop
//   - FP → зупинка + FP journal; FP_CANDIDATE/PASS → до Claude
// ================================================================

const alert     = $input.first().json;
const rule      = alert.rule  || {};
const eventdata = alert.data?.win?.eventdata || {};

const ruleId = String(rule.id    || '');
const level  = Number(rule.level || 0);

function norm(v) {
  return String(v || '').toLowerCase().replace(/\//g, '\\').trim();
}

const img       = norm(eventdata.image);
const cmd       = norm(eventdata.commandLine);
const srcImg    = norm(eventdata.sourceImage);
const tgtImg    = norm(eventdata.targetImage);
const subjUser  = norm(eventdata.subjectUserName);
const tgtUser   = norm(eventdata.targetUserName);
const tgtDomain = norm(eventdata.targetDomainName || '');
const access    = norm(eventdata.grantedAccess);

// Ніколи не silent drop — навіть якщо isFP() = true → FP_CANDIDATE
const NEVER_DROP = new Set([
  '100740','100741','100744','100742',
  '100730','100780','100782','100783','100786','100787',
  '100750','100824','100798','100799',
  '100795','100796','100880',
  '100841','100842','100843','100743',
  '100731',
]);

function classify() {

  // ── 100883: Unsigned DLL ──────────────────────────────────────────
  // imageLoaded ВІДСУТНІЙ у реальних alerts — перевіряємо тільки image
  if (ruleId === '100883') {
    // Безпечний FP — low-attack-surface системні процеси
    const fpImages = [
      'sdiagnhost.exe',               // Windows Diagnostic Host (71 alerts)
      'wiawow64.exe',                 // Windows Image Acquisition (40 alerts)
      'hpseu.ui.wpf.exe',             // HP System Event Utility
      'mfscanutility.exe',            // Scanner utility
      'nvbackend.exe',                // NVIDIA Backend
      'hpsystemeventutilityhost.exe', // HP
      'cmfnss6.exe',                  // Canon scanner
    ];
    if (fpImages.some(n => img.endsWith('\\' + n) || img.endsWith('/' + n))) {
      return { status: 'FP', reason: `${img.split('\\').pop()} — known legitimate app unsigned DLL load` };
    }
    // FP_CANDIDATE — можуть бути проексплоітовані, нехай Claude вирішує
    const candidateImages = [
      'foxitpdfeditor.exe',  // Foxit — PDF exploit target
      'mstsc.exe',           // Remote Desktop — exploit/print driver DLL risk
      'spoolsv.exe',         // Print Spooler — PrintNightmare history
    ];
    if (candidateImages.some(n => img.endsWith('\\' + n) || img.endsWith('/' + n))) {
      return { status: 'FP_CANDIDATE', reason: `${img.split('\\').pop()} — legitimate app but exploit target, Claude to verify` };
    }
    if (img.endsWith('\\rundll32.exe')) {
      return { status: 'FP_CANDIDATE', reason: 'rundll32 loaded unsigned DLL — needs context review' };
    }
  }

  // ── 100882: DLL from writable path ───────────────────────────────
  // imageLoaded ВІДСУТНІЙ — тільки image
  if (ruleId === '100882') {
    if (img.endsWith('\\dismhost.exe')) {
      return { status: 'FP', reason: 'DismHost.exe — Windows DISM system component' };
    }
  }

  // ── 100713: rundll32 ─────────────────────────────────────────────
  // Реальні поля: image, commandLine
  if (ruleId === '100713') {
    const fpCmds = [
      'davclnt.dll,davsetcookie',     // WebDAV mapped drives (fs01, 10.10.95.10)
      'staterepository',              // Windows Store state
      'capabilityaccessmanager',      // Windows capability
      'pcasvc.dll,pcapatchsdbtask',   // Program Compatibility Assistant
      'startupscan.dll,susruntask',   // Windows startup scan
      'appxdeploymentextensions',     // App deployment
      'nvcpl.dll,nvstartup',          // NVIDIA startup
      'nvspcap64.dll,shadowplay',     // NVIDIA ShadowPlay
      'dfrg.exe',                     // Disk defrag (точно, не просто 'dfrg')
      'dfrgntfs.exe',                 // Disk defrag NTFS
      'dfrgfat.exe',                  // Disk defrag FAT
    ];
    if (fpCmds.some(p => cmd.includes(p))) {
      return { status: 'FP', reason: `rundll32 legitimate system/vendor task: ${cmd.slice(0, 80)}` };
    }
  }

  // ── 100716: cmd.exe ──────────────────────────────────────────────
  // Реальні поля: image, commandLine (parentImage ВІДСУТНІЙ!)
  if (ruleId === '100716') {
    // Точна перевірка — тільки відомий Adobe native messaging host
    if (cmd.includes('wcchromenativemessaginghost')) {
      return { status: 'FP', reason: 'Adobe Acrobat Chrome Extension Native Messaging via cmd.exe' };
    }
    // 'acrobat' — занадто широко, може збігтися з payload 'acrobat_helper'
    // → FP_CANDIDATE замість FP
    if (cmd.includes('acrobat') && (cmd.includes('/d') || cmd.includes('/s'))) {
      return { status: 'FP_CANDIDATE', reason: 'cmd.exe with acrobat reference — verify it is genuine Adobe process' };
    }
  }

  // ── 100820: Explicit credential logon (Event 4648) ───────────────
  // Реальні поля: ipAddress, subjectUserName, targetUserName
  // (processName / parentImage ВІДСУТНІ!)
  if (ruleId === '100820') {
    // Machine account → DWM session (Desktop Window Manager)
    if (tgtDomain === 'window manager') {
      return { status: 'FP', reason: 'winlogon.exe DWM session credential — normal Windows session management' };
    }
    // Machine account logon to itself
    if (subjUser && tgtUser && subjUser === tgtUser) {
      return { status: 'FP', reason: 'Machine account self-logon — normal Windows service behavior' };
    }
    // Machine account (ends $) → different user: підозрілий контекст
    if (subjUser.endsWith('$') && tgtUser && !tgtUser.endsWith('$')) {
      return { status: 'FP_CANDIDATE', reason: `Machine account ${subjUser} using explicit creds as user ${tgtUser} — verify` };
    }
  }

  // ── 100870: Pass-the-Hash ─────────────────────────────────────────
  // Не можна підтвердити FP без whitelist IP → до Claude
  if (ruleId === '100870') {
    return { status: 'PASS', reason: 'PtH candidate — requires Claude context analysis' };
  }

  // ── 100830: SeDebugPrivilege ──────────────────────────────────────
  // Реальне поле: subjectUserName тільки, немає process context → до Claude
  if (ruleId === '100830') {
    return { status: 'PASS', reason: 'SeDebugPrivilege — no process context, requires Claude analysis' };
  }

  // ── 100826: Network from suspicious dir ──────────────────────────
  // Реальне поле: тільки image (destinationIp ВІДСУТНІЙ!)
  // ВАЖЛИВО: перевіряємо і ім'я, і що бінарник дійсно в AppData/LocalAppData
  // Це запобігає bypass через перейменування malware у відомий додаток
  if (ruleId === '100826') {
    const fpImages = [
      'vibersandbox.exe',
      'nahimicnotifsys.exe',
      'onedrive.exe',
      'onedrivelauncher.exe',
      'onedrivestandaloneupdater.exe',
      'discord.exe',
      'opera.exe',
      'filecoauth.exe',
      'wps.exe',
      'wpscloudsvr.exe',
    ];
    const inAppData = img.includes('\\appdata\\') || img.includes('\\localappdata\\');
    if (inAppData && fpImages.some(n => img.endsWith('\\' + n) || img.endsWith('/' + n))) {
      return { status: 'FP', reason: `${img.split('\\').pop()} — known legitimate app from AppData` };
    }
    // Відоме ім'я але НЕ в AppData — підозріло
    if (!inAppData && fpImages.some(n => img.endsWith('\\' + n) || img.endsWith('/' + n))) {
      return { status: 'FP_CANDIDATE', reason: `${img.split('\\').pop()} — known app name but unexpected path: ${img}` };
    }
  }

  // ── 100825: C2 LOLBin network ─────────────────────────────────────
  // Немає destinationIp → до Claude
  if (ruleId === '100825') {
    return { status: 'PASS', reason: 'LOLBin network connection — no destination IP in event, needs Claude' };
  }

  // ── 100740: LSASS access ──────────────────────────────────────────
  // Реальні поля: sourceImage, targetImage, grantedAccess
  // ВИПРАВЛЕНО: реальне значення = '0x101000' (НЕ '0x1010' як у ChatGPT!)
  if (ruleId === '100740') {
    if (srcImg.endsWith('\\svchost.exe') && access === '0x101000') {
      return { status: 'FP', reason: 'svchost PROCESS_QUERY_LIMITED_INFORMATION on LSASS — normal Windows behavior' };
    }
    // Все інше — NEVER DROP, до Claude
    return { status: 'PASS', reason: 'LSASS access — requires manual review' };
  }

  // ── 100881: CreateRemoteThread ────────────────────────────────────
  // Реальні поля: sourceImage, targetImage
  // (startModule / startFunction ВІДСУТНІ!)
  if (ruleId === '100881') {
    if (tgtImg.includes('mpcmdrun.exe')) {
      return { status: 'FP_CANDIDATE', reason: 'Unknown process → MpCmdRun.exe — possibly AV scan or injection' };
    }
  }

  return { status: 'PASS', reason: '' };
}

// ── Виконання ─────────────────────────────────────────────────────
const result = classify();

// NEVER DROP override: навіть якщо FP → FP_CANDIDATE (не silent drop)
if (NEVER_DROP.has(ruleId) && result.status === 'FP') {
  result.status = 'FP_CANDIDATE';
  result.reason = '[NEVER_DROP override] ' + result.reason;
}

alert.soc = {
  ...(alert.soc || {}),
  fp_status:          result.status,
  fp_reason:          result.reason,
  requires_ai_review: result.status !== 'FP',
};

if (result.status === 'FP') {
  try {
    const fs   = require('fs');
    const path = require('path');
    const dir  = '/home/node/.n8n/fp-journal';
    fs.mkdirSync(dir, { recursive: true });
    const entry = {
      ts:        new Date().toISOString(),
      source:    'n8n_node2',
      rule_id:   ruleId,
      level,
      agent:     alert.agent?.name || '',
      img,
      cmd,
      fp_reason: result.reason,
    };
    fs.appendFileSync(path.join(dir, 'fp_journal.jsonl'), JSON.stringify(entry) + '\n');
  } catch(e) {}

  return []; // Confirmed FP — stop
}

// FP_CANDIDATE або PASS → до Claude
return [{ json: alert }];
