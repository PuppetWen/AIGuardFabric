import { expect, it } from 'vitest';
import { mergeStdio } from './onboardingStdio';
const template = JSON.stringify({ mcpServers: { guarded: { command: './agf-agent', args: [
  'mcp-proxy', '--server', 'https://platform.example.test', '--', '<ORIGINAL_COMMAND>', '<ORIGINAL_ARGS>',
] } } });
it('preserves the original command and argument vector without treating arguments as shell code', () => {
  const args = ['script.cjs', '--name', 'spaces and quotes "', '$(not-executed)', '--secret-env', 'BUSINESS_SECRET'];
  const result = JSON.parse(mergeStdio(template, 'C:/Program Files/node.exe', JSON.stringify(args)));
  expect(result.mcpServers.guarded.args).toEqual(['mcp-proxy', '--server', 'https://platform.example.test', '--', 'C:/Program Files/node.exe', ...args]);
  expect(result.mcpServers.guarded.command).toBe('./agf-agent'); expect(result.mcpServers.guarded.env).toBeUndefined();
});
it('rejects malformed, unbounded and nonstring original arguments without replacing the business entry', () => {
  for (const args of ['{}', '[1]', '["line\\nvalue"]', JSON.stringify(Array(101).fill('arg'))]) {
    expect(() => mergeStdio(template, 'node', args)).toThrow();
  }
  expect(() => mergeStdio(template, '', '[]')).toThrow();
  expect(() => mergeStdio('{"mcpServers":{"guarded":{"args":["different"]}}}', 'node', '[]')).toThrow('Unsupported stdio template');
});
