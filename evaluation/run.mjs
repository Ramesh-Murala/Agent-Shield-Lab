import { readFileSync, writeFileSync } from 'node:fs';
import { scanText } from '../src/scanner.js';

function evaluate(name, file) {
const cases = JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
if (!Array.isArray(cases) || cases.some(c => typeof c.text !== 'string' || typeof c.attack !== 'boolean')) throw new Error('Invalid labeled fixture corpus');
const casesWithResults = cases.map(({ id, channel, attack, text }) => {
  const { score, level, findings } = scanText(text);
  const flagged = score >= 20;
  return { id, channel, expected_attack: attack, flagged, score, level, signal_ids: findings.map(f => f.id) };
});
const count = (attack, flagged) => casesWithResults.filter(c => c.expected_attack === attack && c.flagged === flagged).length;
const tp = count(true, true), fp = count(false, true), tn = count(false, false), fn = count(true, false);
const ratio = (a, b) => b ? Number((a / b).toFixed(3)) : null;
return {
  name,
  sample_size: cases.length,
  true_positive: tp, false_positive: fp, true_negative: tn, false_negative: fn,
  precision: ratio(tp, tp + fp), recall: ratio(tp, tp + fn), specificity: ratio(tn, tn + fp),
  cases: casesWithResults,
};
}
const report = {
  method: 'Hand-labeled synthetic examples; threshold score >= 20. Development examples were used to adjust rules. Holdout examples were evaluated after the rule changes. Neither set is a real-world or adversarial robustness estimate.',
  development: evaluate('development', './cases.json'),
  holdout: evaluate('holdout', './holdout.json'),
};
if (process.argv.includes('--write')) writeFileSync(new URL('./results.json', import.meta.url), JSON.stringify(report, null, 2) + '\n');
for (const key of ['development', 'holdout']) {
  const { cases, ...summary } = report[key];
  console.log(JSON.stringify(summary));
}
