import type { Definition, Draft, Input, Prepared, Preview, Receipt, Target } from './types';
import { newRequestId } from '@/utils/requestId';
import { revision, uuid } from './text';

export function parseDefinition(text: string): Definition {
  if (new TextEncoder().encode(text).length > 256 * 1024) throw new Error('Definition exceeds 256 KiB / 声明超过 256 KiB');
  const value: unknown = JSON.parse(text);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('A definition object is required / 需要声明对象');
  const doc = value as Record<string, unknown>, keys = ['schema_version', 'tenant_id', 'cloud_team_id', 'inventory_fingerprint', 'nodes'];
  if (Object.keys(doc).some(key => !keys.includes(key)) || doc.schema_version !== 1 || typeof doc.tenant_id !== 'string' || !uuid(doc.tenant_id)
    || typeof doc.cloud_team_id !== 'string' || typeof doc.inventory_fingerprint !== 'string' || !Array.isArray(doc.nodes) || doc.nodes.length > 128) throw new Error('Invalid declaration fields / 声明字段无效');
  for (const value of doc.nodes) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid node / 节点无效');
    const node = value as Record<string, unknown>;
    if (Object.keys(node).some(key => !['node_id', 'name', 'agent_ids', 'depends_on', 'trigger', 'cron'].includes(key))
      || typeof node.node_id !== 'string' || typeof node.name !== 'string' || !Array.isArray(node.agent_ids) || !Array.isArray(node.depends_on)
      || !node.agent_ids.every(item => typeof item === 'string') || !node.depends_on.every(item => typeof item === 'string')
      || typeof node.trigger !== 'string' || !['manual', 'event', 'cron'].includes(node.trigger) || (node.cron !== undefined && node.cron !== null && typeof node.cron !== 'string')) throw new Error('Unsupported or invalid node fields / 不支持或无效的节点字段');
  }
  return value as Definition;
}
export function choose(target: Target): Draft {
  return { target, expectedVersion: target.current?.version ?? 0, text: JSON.stringify(target.current?.local ?? target.template, null, 2),
    action: 'save_definition', direction: 'push', confirmed: false, mockConfirmed: false, sourceConfirmed: false };
}
export function adopt(draft: Draft, target: Target): Draft {
  const definition = parseDefinition(draft.text);
  return { ...draft, target, expectedVersion: target.current?.version ?? 0,
    text: JSON.stringify({ ...target.template, nodes: definition.nodes }, null, 2), confirmed: false, mockConfirmed: false, sourceConfirmed: false };
}
export function input(draft: Draft): Input {
  if (!revision(draft.expectedVersion) || !revision(draft.target.source.configurationVersion) || draft.target.source.configurationVersion === 0) throw new Error('Revision cannot be safely represented / 版本不能安全表示');
  return { request_id: newRequestId(), expected_version: draft.expectedVersion, configuration_version: draft.target.source.configurationVersion,
    inventory_fingerprint: draft.target.source.inventoryFingerprint, confirm_application_owned: draft.confirmed,
    confirm_mock_sync: draft.mockConfirmed, confirm_source_change: draft.sourceConfirmed,
    change: draft.action === 'save_definition' ? { action: 'save_definition', definition: parseDefinition(draft.text) } : { action: 'sync', direction: draft.direction } };
}
export function immutable(value: Input): Readonly<Input> {
  if (value.change.action === 'save_definition') {
    value.change.definition.nodes.forEach(node => { Object.freeze(node.agent_ids); Object.freeze(node.depends_on); Object.freeze(node); });
    Object.freeze(value.change.definition.nodes); Object.freeze(value.change.definition);
  }
  Object.freeze(value.change); return Object.freeze(value);
}
export function matchingPreview(value: Preview, team: string, body: Input) {
  return value.previewOnly === true && value.providerCalled === false && value.consumerApplied === null
    && value.teamName === team && value.requestId === body.request_id && value.expectedVersion === body.expected_version
    && value.configurationVersion === body.configuration_version && value.result.teamName === team
    && value.result.version === body.expected_version + 1 && value.result.source.configurationVersion === body.configuration_version
    && value.result.source.inventoryFingerprint === body.inventory_fingerprint;
}
export function matching(receipt: Receipt, prepared?: Prepared, request = receipt.requestId) {
  return uuid(receipt.requestId) && receipt.requestId === request && receipt.status === 'committed' && receipt.immutable === true
    && receipt.providerCalled === false && receipt.consumerApplied === null && /^[0-9a-f]{64}$/i.test(receipt.bodyHash)
    && revision(receipt.version) && receipt.version > 0 && (!prepared || (receipt.teamName === prepared.team
      && receipt.version === prepared.body.expected_version + 1 && receipt.source.configurationVersion === prepared.body.configuration_version
      && receipt.action === prepared.body.change.action && (prepared.body.change.action !== 'sync' || receipt.direction === prepared.body.change.direction)));
}
