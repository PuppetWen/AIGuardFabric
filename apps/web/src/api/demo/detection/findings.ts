import type { EvidenceItem, Finding } from '@/types/domain';

import { agoHours } from '../../../utils/time';
import { demoAssetById } from '../assets';

import { findingSeeds } from './finding-seeds';
import { ruleNameFor } from './rule-names';

/* ------------------------------------------------------------------ */
/* Findings                                                            */
/* ------------------------------------------------------------------ */

function evidenceChain(id: string, assetName: string, seed: number): EvidenceItem[] {
  return [
    {
      id: `${id}-ev-1`,
      kind: 'request',
      label: '触发请求',
      content: [
        `POST /mcp/v1/tools/call HTTP/1.1`,
        `Host: mcp-proxy.intra.acme:9443`,
        `X-AGF-Agent: ${assetName}`,
        `Content-Type: application/json`,
        ``,
        `{"tool":"${seed % 2 === 0 ? 'run_command' : 'execute_query'}","arguments":{...}}`,
      ].join('\n'),
      capturedAt: agoHours(6),
    },
    {
      id: `${id}-ev-2`,
      kind: 'response',
      label: '目标响应（关键片段）',
      content: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"result":"<redacted 1.2KB>","elapsed_ms":${120 + (seed % 90)}}`,
      capturedAt: agoHours(5.9),
    },
    {
      id: `${id}-ev-3`,
      kind: 'log',
      label: '网关审计日志',
      content: `agf-gateway[${240 + (seed % 60)}]: policy=pol-egress-deny action=deny reason="outbound target outside allow-list" agent=${assetName}`,
      capturedAt: agoHours(5.8),
    },
    {
      id: `${id}-ev-4`,
      kind: 'artifact',
      label: '证据产物',
      content: `evidence/${id}/payload.bin (sha256:${id.replace(/\D/g, '').padEnd(8, '0')}a91f4c2d8e77b0${(seed % 97).toString().padStart(2, '0')})`,
      capturedAt: agoHours(5.7),
    },
  ];
}

export const demoFindings: Finding[] = findingSeeds.map((seed) => {
  const asset = demoAssetById.get(seed.assetId);
  return {
    id: seed.id,
    title: seed.title,
    severity: seed.severity,
    domain: seed.domain,
    status: seed.status,
    target: asset?.name ?? seed.assetId,
    assetId: seed.assetId,
    assetName: asset?.name ?? seed.assetId,
    detectedAt: agoHours(seed.detectedHours),
    updatedAt: agoHours(seed.updatedHours),
    ruleId: seed.ruleId,
    ruleName: ruleNameFor(seed.ruleId),
    summary: seed.summary,
    description: seed.description,
    evidence: evidenceChain(seed.id, asset?.name ?? seed.assetId, seed.detectedHours),
    triple: seed.triple,
    callChain: seed.callChain,
    remediation: seed.remediation,
    cvss: seed.cvss,
    cwe: seed.cwe,
    llmVerdict: seed.llm,
    assignee: seed.assignee,
  };
});
