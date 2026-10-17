import { list, mapped, measurement, number, object, riskDomain, strings, text, type ApiObject } from './shared';
import { normalizePolicyAction } from '../policyActions';

export function finding(raw: ApiObject): ApiObject {
  const judgement = object(raw.llmVerdict);
  const verdict = Object.keys(judgement).length ? {
    ...judgement,
    model: text(judgement.model),
    verdict: mapped(judgement.verdict, { malicious: 'true-positive', benign: 'false-positive', suspicious: 'inconclusive' }, 'inconclusive'),
    confidence: measurement(judgement.confidence),
    reasoning: text(judgement.reasoning ?? judgement.rationale ?? judgement.reason),
    reviewedAt: text(judgement.reviewedAt ?? judgement.judgedAt ?? judgement.at),
  } : null;
  return {
    ...raw, domain: riskDomain(raw.domain),
    ...(raw.sourceOrigin === 'correlation-analysis' ? {
      correlationAnalysis: { rule: text(raw.description), details: text(raw.chain) }, description: '',
    } : {}),
    status: raw.status ?? raw.state,
    assetName: text(raw.assetName, text(raw.assetId, '—')),
    detectedAt: text(raw.detectedAt ?? raw.firstSeenAt ?? raw.createdAt),
    ruleId: raw.ruleId ?? strings(raw.ruleKeys)[0] ?? strings(raw.ruleIds)[0] ?? '',
    ruleName: raw.ruleName ?? strings(raw.ruleKeys).join(', '),
    evidence: list(raw.evidence).map((item, index) => {
      const entry = object(item);
      return {
        ...entry, id: text(entry.id ?? entry.code, String(index)),
        kind: mapped(entry.kind, { scan: 'log', 'raw-log': 'log', packet: 'payload' }),
        label: text(entry.label ?? entry.summary ?? entry.code),
        content: text(entry.content ?? entry.summary ?? entry.contentHash),
        capturedAt: text(entry.capturedAt ?? entry.collectedAt),
      };
    }),
    triple: raw.triple ?? { baseline: text(raw.baseline), diff: text(raw.diffEvidence), markerEcho: text(raw.markerEcho) },
    callChain: raw.callChain ?? text(raw.chain).split(/\s*(?:→|->|\r?\n)\s*/).filter(Boolean),
    remediation: text(raw.remediation ?? raw.fix),
    cvss: text(raw.cvss, '—'), assignee: raw.assignee ?? null,
    llmVerdict: verdict,
  };
}

export function rule(raw: ApiObject): ApiObject {
  return {
    ...raw, id: text(raw.id ?? raw.key), domain: riskDomain(raw.domain),
    readOnly: raw.readOnly ?? true,
    version: text(raw.version), lifecycle: raw.lifecycle ?? 'unknown',
    hitCount24h: measurement(raw.hitCount24h), falsePositiveRate: measurement(raw.falsePositiveRate),
    updatedAt: text(raw.updatedAt),
  };
}

export function policy(raw: ApiObject): ApiObject {
  const signature = object(raw.signature);
  return {
    ...raw, action: normalizePolicyAction(raw.action), rawAction: text(raw.rawAction ?? raw.action),
    lifecycle: raw.lifecycle ?? (!raw.enabled ? 'disabled' : raw.dryRun ? 'dry-run' : 'enforced'),
    expression: text(raw.expression ?? raw.source),
    code: raw.language === 'structured' ? JSON.stringify(raw.structured ?? {}, null, 2) : text(raw.code ?? raw.source),
    codeLanguage: raw.codeLanguage ?? raw.language ?? 'cel',
    interceptPoints: list(raw.interceptPoints),
    hitCount24h: measurement(raw.hitCount24h), blockedCount24h: measurement(raw.blockedCount24h),
    signature: Object.keys(signature).length ? signature : {
      status: raw.signature ? 'signed' : 'unsigned', signer: '', keyId: '',
      digest: text(raw.contentHash), signedAt: null,
    },
    author: text(raw.author, '—'),
  };
}

export function campaign(raw: ApiObject): ApiObject {
  const executed = number(raw.executedCases);
  const succeeded = number(raw.succeeded ?? raw.succeededCases);
  return {
    ...raw,
    status: mapped(raw.status ?? raw.state, { completed: 'succeeded', queued: 'planned', created: 'planned', cancelled: 'aborted' }),
    targets: raw.targets ?? [...strings(raw.targetAgentIds), ...strings(raw.targetMcpIds)],
    categories: strings(raw.categories),
    succeeded, blocked: measurement(raw.blocked), bypassed: measurement(raw.bypassed),
    successRate: Object.prototype.hasOwnProperty.call(raw, 'successRate') ? measurement(raw.successRate) : (executed ? succeeded / executed : null),
    operator: text(raw.operator ?? raw.launchedBy),
    ciGateEnabled: raw.ciGateEnabled ?? raw.ciGate ?? false,
    severityThreshold: raw.severityThreshold ?? 'critical',
    finishedAt: raw.finishedAt ?? null,
  };
}
