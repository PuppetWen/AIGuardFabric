import type { InterceptEvent } from '@/types/domain';

export interface ToolActivity {
  name: string;
  checks: number;
  blocked: number;
  lastSeen: string;
}

const BLOCKED_ACTIONS = new Set(['deny', 'throttle', 'quarantine']);

/** Count checked MCP tool requests only; response frames have no tool name. */
export function toolActivity24h(events: readonly InterceptEvent[], now = Date.now()): ToolActivity[] {
  const since = now - 24 * 60 * 60 * 1000;
  const rows = new Map<string, ToolActivity>();
  for (const event of events) {
    if (event.point !== 'mcp-proxy') continue;
    const name = event.toolName?.trim();
    const at = Date.parse(event.ts);
    if (!name || !Number.isFinite(at) || at < since || at > now) continue;
    const row = rows.get(name) ?? { name, checks: 0, blocked: 0, lastSeen: event.ts };
    row.checks += 1;
    if (BLOCKED_ACTIONS.has(event.action)) row.blocked += 1;
    if (at > Date.parse(row.lastSeen)) row.lastSeen = event.ts;
    rows.set(name, row);
  }
  return [...rows.values()].sort((a, b) => b.checks - a.checks || a.name.localeCompare(b.name));
}
