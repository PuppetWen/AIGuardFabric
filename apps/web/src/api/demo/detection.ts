import type { RuleTestResult } from '@/types/domain';

import { demoRules } from './detection/rules';
import { buildRuleTestResult } from './detection/rule-samples';

export const demoRuleTestResults: Record<string, RuleTestResult> = Object.fromEntries(
  demoRules.map((rule) => [rule.id, buildRuleTestResult(rule.id)]),
);

/* ------------------------------------------------------------------ */
/* Findings, rules & rule-name registry (split out, re-exported here)   */
/* ------------------------------------------------------------------ */

export { demoFindings } from './detection/findings';
export { demoRules } from './detection/rules';
export { buildRuleTestResult } from './detection/rule-samples';
export { ruleNameFor, RULE_NAMES } from './detection/rule-names';
