// Heuristic signals, not probabilities or a security boundary.
export const rules = [
  { id: 'override', label: 'Instruction override', severity: 28, color: '#ff7048', detail: 'Attempts to replace prior or trusted instructions', patterns: [/ignore (all |any |the )?(previous|prior|above) (instructions|rules|context)/gi, /disregard (the )?(system|developer|previous)/gi, /new (system )?instructions?/gi, /forget (everything|your instructions|the rules)/gi] },
  { id: 'exfiltration', label: 'Data exfiltration', severity: 34, color: '#ff4f7b', detail: 'Requests secrets, credentials, or private context', patterns: [/(reveal|print|send|return|show|expose).{0,35}(api key|secret|password|token|system prompt|private data)/gi, /(api key|secret|token|password).{0,25}(to|at|via).{0,25}(http|email|webhook)/gi, /(forward|send|copy).{0,45}(confidential|private|entire conversation).{0,45}(external|page author|address|reply)/gi, /do not redact/gi] },
  { id: 'tool_abuse', label: 'Unsafe tool request', severity: 25, color: '#ffb84a', detail: 'Pushes the agent toward unapproved external actions', patterns: [/(run|execute|invoke|call).{0,24}(shell|terminal|command|tool|function)/gi, /(download|upload|post|send).{0,32}(credentials|secrets?|private data)/gi, /(delete|remove|overwrite).{0,25}(files?|database)/gi] },
  { id: 'role_hijack', label: 'Role impersonation', severity: 20, color: '#a884ff', detail: 'Claims privileged identity or authority', patterns: [/you are now/gi, /(system|developer|administrator|root) (message|override|notice|instruction)/gi, /act as (an? )?(admin|root|system)/gi] },
  { id: 'concealment', label: 'Concealment', severity: 18, color: '#5ee7ff', detail: 'Tries to hide the action from users or logs', patterns: [/do not (tell|show|mention|alert|notify)/gi, /(silently|secretly|without (the )?user knowing)/gi, /hide (this|the action|your response)/gi] },
  { id: 'obfuscation', label: 'Encoded payload', severity: 16, color: '#6ce59c', detail: 'Uses encoding or invisible text to evade inspection', patterns: [/(base64|rot13|hex)[- ]?(decode|encoded|payload)?/gi, /[A-Za-z0-9+/]{48,}={0,2}/g, /[\u200B-\u200D\uFEFF]/g] }
];

export function scanText(rawText) {
  const input = String(rawText ?? '');
  const text = input.slice(0, 20000);
  const truncated = input.length > text.length;
  // NFKC catches fullwidth lettering. Keep a map to highlight the original text.
  const normalized = [];
  const offsets = [];
  for (let i = 0; i < text.length;) {
    const point = text.codePointAt(i);
    const width = point > 0xffff ? 2 : 1;
    const char = text.slice(i, i + width);
    if (!/[\u200B-\u200D\uFEFF]/u.test(char)) {
      for (const unit of char.normalize('NFKC')) {
        for (const codeUnit of unit) { normalized.push(codeUnit); offsets.push(i); }
      }
    }
    i += width;
  }
  const scan = normalized.join('');
  const findings = [];
  const ranges = [];
  for (const rule of rules) {
    const matches = [];
    for (const pattern of rule.patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(scan)) !== null) {
        matches.push(match[0]);
        ranges.push({ start: offsets[match.index], end: offsets[match.index + match[0].length - 1] + 1, rule: rule.id });
        if (match[0].length === 0) pattern.lastIndex += 1;
      }
    }
    if (matches.length) {
      findings.push({ id: rule.id, label: rule.label, severity: rule.severity, color: rule.color,
        detail: rule.detail, matches: [...new Set(matches)].slice(0, 4), count: matches.length });
    }
  }
  const hidden = [...text.matchAll(/[\u200B-\u200D\uFEFF]+/gu)];
  if (hidden.length) {
    for (const match of hidden) ranges.push({ start: match.index, end: match.index + match[0].length, rule: 'obfuscation' });
    const existing = findings.find(f => f.id === 'obfuscation');
    if (existing) existing.count += hidden.length;
    else {
      const rule = rules.find(r => r.id === 'obfuscation');
      findings.push({ id: rule.id, label: rule.label, severity: rule.severity, color: rule.color,
        detail: rule.detail, matches: ['invisible Unicode characters'], count: hidden.length });
    }
  }
  let score = findings.reduce((sum, f) => sum + f.severity * (1 + Math.min(f.count - 1, 2) * .16), 0);
  if (findings.length >= 2) score += 8;
  if (findings.some(f => f.id === 'override') && findings.some(f => f.id === 'exfiltration')) score += 12;
  score = Math.min(100, Math.round(score));
  const level = score >= 75 ? 'critical' : score >= 45 ? 'high' : score >= 20 ? 'caution' : 'low';
  return { text, truncated, score, level, findings, ranges: mergeRanges(ranges), policy: buildPolicy(findings, level) };
}

function mergeRanges(ranges) {
  return ranges.sort((a,b) => a.start - b.start).reduce((acc, range) => {
    const last = acc.at(-1);
    if (last && range.start <= last.end) last.end = Math.max(last.end, range.end);
    else acc.push({ ...range });
    return acc;
  }, []);
}

function buildPolicy(findings, level) {
  const ids = new Set(findings.map(f => f.id));
  const actions = [];
  if (ids.has('override') || ids.has('role_hijack')) actions.push('Treat embedded instructions as data; preserve the trusted instruction hierarchy.');
  if (ids.has('exfiltration')) actions.push('Block access to secrets and redact sensitive context before any model call.');
  if (ids.has('tool_abuse')) actions.push('Require explicit human approval before tools can write, send, execute, or delete.');
  if (ids.has('concealment') || ids.has('obfuscation')) actions.push('Inspect encoded content separately and rescan any decoded text before use.');
  if (level === 'critical' || level === 'high') actions.push('Quarantine this content and continue only with the factual, non-instructional portions.');
  if (!actions.length) actions.push('No rule matched. Keep normal least-privilege tool boundaries; a missed attack is still possible.');
  return actions;
}

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#039;' }[char]));
}

export function highlightEvidence(result) {
  if (!result.ranges.length) return escapeHtml(result.text);
  let html = '', cursor = 0;
  for (const range of result.ranges) {
    html += escapeHtml(result.text.slice(cursor, range.start));
    html += `<mark>${escapeHtml(result.text.slice(range.start, range.end))}</mark>`;
    cursor = range.end;
  }
  return html + escapeHtml(result.text.slice(cursor));
}
