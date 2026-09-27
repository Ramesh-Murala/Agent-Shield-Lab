import { scanText } from './scanner.js';

/** Keep flagged text out of the next agent step; the caller owns enforcement. */
export function gateUntrustedContent(input) {
  const report = scanText(input);
  if (report.truncated) return { decision: 'quarantine', content: null, report, reason: 'Input exceeds scan limit' };
  if (report.score >= 20) return { decision: 'review', content: null, report, reason: 'Review detected signals before forwarding' };
  return { decision: 'pass', content: report.text, report, reason: 'No rule matched; maintain independent tool permissions' };
}
