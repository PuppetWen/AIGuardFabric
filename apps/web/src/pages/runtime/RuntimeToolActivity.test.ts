import { describe, expect, it } from 'vitest';
import type { InterceptEvent } from '@/types/domain';
import { toolActivity24h } from './toolActivity';

const now = Date.parse('2026-09-29T12:00:00Z');
function event(toolName: string | null, action: InterceptEvent['action'], ts = '2026-09-29T11:00:00Z',
  point: InterceptEvent['point'] = 'mcp-proxy'): InterceptEvent {
  return { id: `${toolName}-${action}-${ts}`, ts, point, agentName: '-', mcpName: null, toolName,
    action, policyName: '-', reason: '', payloadDigest: '', latencyMs: 0, severity: 'info' };
}

describe('MCP tool activity from saved interception records', () => {
  it('counts checked tool requests and blocks without treating response frames as another call', () => {
    expect(toolActivity24h([
      event('read_asset', 'allow'), event(null, 'allow'),
      event('read_asset', 'deny'), event('read_asset', 'throttle'),
      event('read_asset', 'allow', '2026-09-28T11:59:59Z'),
      event('read_asset', 'deny', '2026-09-29T13:00:00Z'),
      event('read_asset', 'deny', '2026-09-29T11:30:00Z', 'ai-gateway'),
      event('write_asset', 'quarantine', '2026-09-29T11:30:00Z'),
    ], now)).toEqual([
      { name: 'read_asset', checks: 3, blocked: 2, lastSeen: '2026-09-29T11:00:00Z' },
      { name: 'write_asset', checks: 1, blocked: 1, lastSeen: '2026-09-29T11:30:00Z' },
    ]);
  });
});
