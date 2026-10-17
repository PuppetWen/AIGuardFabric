import { demoMcpServers } from './runtime/servers';
import { demoMcpTools } from './runtime/tools';

// Backfill `toolCount` on the servers from the tool inventory.
for (const server of demoMcpServers) {
  server.toolCount = demoMcpTools.filter((tool) => tool.serverId === server.id).length;
}

export { demoAgents } from './runtime/agents';
export { demoMcpServers } from './runtime/servers';
export { demoMcpTools, toolsForServer } from './runtime/tools';
